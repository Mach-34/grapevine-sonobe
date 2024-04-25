use ark_circom::circom::CircomCircuit;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::fmt::Debug;
use num_bigint::BigInt;
use sonobe::{frontend::FCircuit, Error as SonobeError};
use std::path::PathBuf;

use crate::errors::GrapevineError;
use crate::utils::wrapper::{CircomPrivateInput, CircomWrapper};

// Define Circom FCircuit
#[derive(Clone, Debug)]
pub struct GrapevineFCircuit<F: PrimeField> {
    circom_wrapper: CircomWrapper<F>,
    private_input: CircomPrivateInput,
}

impl<F: PrimeField> GrapevineFCircuit<F> {
    pub fn set_private_input(&mut self, input: CircomPrivateInput) {
        self.private_input = input;
    }
}

impl<F: PrimeField> FCircuit<F> for GrapevineFCircuit<F> {
    type Params = (PathBuf, PathBuf);

    fn new(params: Self::Params) -> Self {
        let (r1cs_path, wasm_path) = params;
        let circom_wrapper = CircomWrapper::new(r1cs_path, wasm_path);
        Self {
            circom_wrapper,
            private_input: CircomPrivateInput::empty(false),
        }
    }

    fn state_len(&self) -> usize {
        4
    }

    fn step_native(&self, _i: usize, z_i: Vec<F>) -> Result<Vec<F>, SonobeError> {
        // convert ivc_input from ark ff to BigInt
        let ivc_input = z_i
            .iter()
            .map(|val| CircomWrapper::ark_primefield_to_num_bigint(*val))
            .collect::<Vec<BigInt>>();
        let mut inputs = vec![("ivc_input".to_string(), ivc_input)];

        // set the private inputs
        if self.private_input.uninitialized() {
            return Err(SonobeError::Other("Private input not set".to_string()));
        }
        let private_input = CircomWrapper::<F>::marshal_private_inputs(&self.private_input);
        inputs.extend(private_input);

        // calculate witness
        let witness = self.circom_wrapper.extract_witness(&inputs).map_err(|e| {
            SonobeError::WitnessCalculationError(format!("Failed to calculate witness: {}", e))
        })?;

        // extract the z_i1 (next state) from witvec
        let z_i1 = witness[1..1 + self.state_len()].to_vec();
        Ok(z_i1)
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // convert ivc input from FpVar to ark ff to BigInt
        let ivc_input: Vec<BigInt> = z_i
            .iter()
            .map(|val| CircomWrapper::ark_primefield_to_num_bigint(val.value().unwrap()))
            .collect();
        let mut inputs = vec![("ivc_input".to_string(), ivc_input)];

        // set the private inputs
        if self.private_input.uninitialized() {
            return Err(SynthesisError::AssignmentMissing);
        }
        let private_input = CircomWrapper::<F>::marshal_private_inputs(&self.private_input);
        inputs.extend(private_input);

        println!("Inputs: {:?}", inputs);

        // extract r1cs and witness
        let (r1cs, witness) = self
            .circom_wrapper
            .extract_r1cs_and_witness(&inputs)
            .map_err(|_| SynthesisError::AssignmentMissing)?;

        println!("Wire map len: {:?}", r1cs.clone().wire_mapping.unwrap().len());
        println!("Constraints len: {:?}", r1cs.clone().constraints.len());
        println!("Witness len: {:?}", witness.clone().unwrap().len());

        // Initialize CircomCircuit
        let circom_circuit = CircomCircuit {
            r1cs,
            witness: witness.clone(),
            inputs_already_computed: false,
        };

        circom_circuit
            .generate_constraints(cs.clone())
            .map_err(|_| SynthesisError::Unsatisfiable)?;

        if !cs.is_satisfied().unwrap() {
            return Err(SynthesisError::Unsatisfiable);
        };

        let w = witness.ok_or(SynthesisError::Unsatisfiable)?;

        let z_i1: Vec<FpVar<F>> =
            Vec::<FpVar<F>>::new_witness(cs.clone(), || Ok(w[1..1 + self.state_len()].to_vec()))?;

        Ok(z_i1)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::params::test_nova_setup;
    use crate::utils::{
        inputs::{get_z0, random_f_bigint},
        wrapper::CircomPrivateInput,
    };
    use ark_pallas::{constraints::GVar, Fr, Projective};
    use ark_r1cs_std::alloc::AllocVar;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_vesta::{constraints::GVar as GVar2, Projective as Projective2};
    use lazy_static::lazy_static;
    use num_bigint::BigInt;
    use sonobe::{
        commitment::pedersen::Pedersen, folding::nova::Nova,
        transcript::poseidon::poseidon_test_config, Error, FoldingScheme,
    };
    use std::env::current_dir;
    use std::time::Instant;

    lazy_static! {
        pub static ref R1CS_PATH: PathBuf = PathBuf::from("./circom/artifacts/grapevine.r1cs");
        pub static ref WASM_PATH: PathBuf = PathBuf::from("./circom/artifacts/grapevine.wasm");
        pub static ref PHRASE: String = String::from("This is a secret");
        pub static ref USERNAMES: [String; 5] = [
            String::from("alice"),
            String::from("bob"),
            String::from("charlie"),
            String::from("david"),
            String::from("eve")
        ];
        pub static ref AUTH_SECRETS: [BigInt; 5] = (0..5)
            .map(|_| random_f_bigint::<Fr>())
            .collect::<Vec<BigInt>>()
            .try_into()
            .unwrap();
    }

    #[test]
    fn test_step_native() {
        // define inputs
        let step_0_inputs = CircomPrivateInput {
            phrase: Some(String::from(&*PHRASE)),
            usernames: [None, Some(String::from(&*USERNAMES[0]))],
            auth_secrets: [None, Some(AUTH_SECRETS[0].clone())],
            chaff: false,
        };
        let z_0 = get_z0();

        // initialize new Grapevine function circuit
        let mut f_circuit = GrapevineFCircuit::<Fr>::new((R1CS_PATH.clone(), WASM_PATH.clone()));
        f_circuit.set_private_input(step_0_inputs);

        let z_1 = f_circuit.step_native(0, z_0.to_vec()).unwrap();
        println!("z_1: {:?}", z_1);
    }

    #[test]
    fn test_step_constraints() {
        // initialize new Grapevine function circuit
        let mut f_circuit = GrapevineFCircuit::<Fr>::new((R1CS_PATH.clone(), WASM_PATH.clone()));

        // define inputs
        let step_0_inputs = CircomPrivateInput {
            phrase: Some(String::from(&*PHRASE)),
            usernames: [None, Some(String::from(&*USERNAMES[0]))],
            auth_secrets: [None, Some(AUTH_SECRETS[0].clone())],
            chaff: false,
        };
        f_circuit.set_private_input(step_0_inputs);

        // assign z0
        let cs = ConstraintSystem::<Fr>::new_ref();
        let z_0_var = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(get_z0())).unwrap();

        // compute constraints for step 0
        let cs = ConstraintSystem::<Fr>::new_ref();
        let z_1_var = f_circuit
            .generate_step_constraints(cs.clone(), 1, z_0_var)
            .unwrap();
        println!("z_1: {:?}", z_1_var);

        // assert_eq!(z_i1_var.value().unwrap(), vec![Fr::from(38), Fr::from(1)]);
    }

    #[test]
    fn test_multiple_steps_native() {
        // initialize new Grapevine function circuit
        let mut f_circuit = GrapevineFCircuit::<Fr>::new((R1CS_PATH.clone(), WASM_PATH.clone()));

        /*  DEGREE 1  */
        // define degree 1 logic inputs
        let inputs = CircomPrivateInput {
            phrase: Some(String::from(&*PHRASE)),
            usernames: [None, Some(String::from(&*USERNAMES[0]))],
            auth_secrets: [None, Some(AUTH_SECRETS[0].clone())],
            chaff: false,
        };
        f_circuit.set_private_input(inputs);

        // compute step 0 (degree 1 logic step)
        let z_i = f_circuit.step_native(0, get_z0().to_vec()).unwrap();

        // define degree 1 chaff inputs
        let inputs = CircomPrivateInput::empty(true);
        f_circuit.set_private_input(inputs);

        // compute step 1 (degree 1 chaff step)
        let z_i = f_circuit.step_native(1, z_i.to_vec()).unwrap();
        println!("z_i: {:?}", z_i);

        /*  DEGREE 2  */
        // define degree 2 logic inputs
        let inputs = CircomPrivateInput {
            phrase: None,
            usernames: [
                Some(String::from(&*USERNAMES[0])),
                Some(String::from(&*USERNAMES[1])),
            ],
            auth_secrets: [Some(AUTH_SECRETS[0].clone()), Some(AUTH_SECRETS[1].clone())],
            chaff: false,
        };
        f_circuit.set_private_input(inputs);

        // compute step 2 (degree 2 logic step)
        let z_i = f_circuit.step_native(2, z_i.to_vec()).unwrap();

        // define degree 2 chaff inputs
        let inputs = CircomPrivateInput::empty(true);
        f_circuit.set_private_input(inputs);

        // compute step 3 (degree 2 chaff step)
        let z_i = f_circuit.step_native(3, z_i.to_vec()).unwrap();

        /*  DEGREE 3  */
        // define degree 3 logic inputs
        let inputs = CircomPrivateInput {
            phrase: None,
            usernames: [
                Some(String::from(&*USERNAMES[1])),
                Some(String::from(&*USERNAMES[2])),
            ],
            auth_secrets: [Some(AUTH_SECRETS[1].clone()), Some(AUTH_SECRETS[2].clone())],
            chaff: false,
        };
        f_circuit.set_private_input(inputs);

        // compute step 4 (degree 3 logic step)
        let z_i = f_circuit.step_native(4, z_i.to_vec()).unwrap();

        // define degree 3 chaff inputs
        let inputs = CircomPrivateInput::empty(true);
        f_circuit.set_private_input(inputs);

        // compute step 5 (degree 3 chaff step)
        let z_i = f_circuit.step_native(5, z_i.to_vec()).unwrap();

        /* RESULT */
        // @todo: compute hashes natively
        assert_eq!(z_i[0], Fr::from(3));
        assert_eq!(z_i[3], Fr::from(0));
    }

    // #[test]
    // fn test_multiple_steps_constraints() {
    //     // initialize new Grapevine function circuit
    //     let mut f_circuit = GrapevineFCircuit::<Fr>::new((R1CS_PATH.clone(), WASM_PATH.clone()));
    //
    //     /*  DEGREE 1  */
    //     // define degree 1 logic inputs
    //     let inputs = CircomPrivateInput {
    //         phrase: Some(String::from(&*PHRASE)),
    //         usernames: [None, Some(String::from(&*USERNAMES[0]))],
    //         auth_secrets: [None, Some(AUTH_SECRETS[0].clone())],
    //         chaff: false
    //     };
    //     f_circuit.set_private_input(inputs);
    //
    //     // assign z0
    //     let cs = ConstraintSystem::<Fr>::new_ref();
    //     let z_0_var = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(get_z0())).unwrap();
    //
    //     // compute constraints for step 0 (degree 1 logic step)
    //     let cs = ConstraintSystem::<Fr>::new_ref();
    //     let z_1_var = f_circuit
    //         .generate_step_constraints(cs.clone(), 0, z_0_var)
    //         .unwrap();
    //     println!("z_1: {:?}", z_1_var);
    //
    //     // define degree 1 chaff inputs
    //     let inputs = CircomPrivateInput::empty(true);
    //     f_circuit.set_private_input(inputs);
    //
    //     // compute step 1 (degree 1 chaff step)
    //     let z_i = f_circuit.step_native(1, z_i.to_vec()).unwrap();
    //     println!("z_i: {:?}", z_i);
    //
    //     // define inputs
    //     let step_0_inputs = CircomPrivateInput {
    //         phrase: Some(String::from(&*PHRASE)),
    //         usernames: [None, Some(String::from(&*USERNAMES[0]))],
    //         auth_secrets: [None, Some(AUTH_SECRETS[0].clone())],
    //         chaff: false
    //     };
    //
    //     // initialize new Grapevine function circuit
    //     let mut f_circuit = GrapevineFCircuit::<Fr>::new((R1CS_PATH.clone(), WASM_PATH.clone()));
    //     f_circuit.set_private_input(step_0_inputs);
    //
    // }

    #[test]
    fn test_full_one_step() {
        // initialize new Grapevine function circuit
        let mut f_circuit = GrapevineFCircuit::<Fr>::new((R1CS_PATH.clone(), WASM_PATH.clone()));

        // Get test params
        let (prover_params, verifier_params) =
            test_nova_setup::<GrapevineFCircuit<Fr>>(f_circuit.clone());
        

        // define inputs
        // define inputs
        let step_0_inputs = CircomPrivateInput {
            phrase: Some(String::from(&*PHRASE)),
            usernames: [None, Some(String::from(&*USERNAMES[0]))],
            auth_secrets: [None, Some(AUTH_SECRETS[0].clone())],
            chaff: false,
        };
        // let z_0 = get_z0();
    }

    #[test]
    fn test_full() {
        let num_steps = 10;
        let initial_state = vec![Fr::from(19), Fr::from(0)];

        let r1cs_path = PathBuf::from("./circom/artifacts/grapevine.r1cs");
        let wasm_path = PathBuf::from("./circom/artifacts/grapevine.wasm");

        let f_circuit = GrapevineFCircuit::<Fr>::new((r1cs_path, wasm_path));

        let start = Instant::now();
        println!("Generating params...");
        let (prover_params, verifier_params) =
            test_nova_setup::<GrapevineFCircuit<Fr>>(f_circuit.clone());
        println!("Generated params: {:?}", start.elapsed());
        type NOVA = Nova<
            Projective,
            GVar,
            Projective2,
            GVar2,
            GrapevineFCircuit<Fr>,
            Pedersen<Projective>,
            Pedersen<Projective2>,
        >;

        let start = Instant::now();
        println!("Initializing folding scheme...");
        let mut folding_scheme =
            NOVA::init(&prover_params, f_circuit, initial_state.clone()).unwrap();
        println!("Initialized folding scheme: {:?}", start.elapsed());

        for i in 0..num_steps {
            let start = Instant::now();
            folding_scheme.prove_step().unwrap();
            println!("Proved step {}: {:?}", i, start.elapsed());
        }

        let (running_instance, incoming_instance, cyclefold_instance) = folding_scheme.instances();

        println!("Running IVC Verifier...");
        let start = Instant::now();
        NOVA::verify(
            verifier_params,
            initial_state.clone(),
            folding_scheme.state(),
            Fr::from(num_steps as u32),
            running_instance,
            incoming_instance,
            cyclefold_instance,
        )
        .unwrap();
        println!("Verified: {:?}", start.elapsed());
    }
}
