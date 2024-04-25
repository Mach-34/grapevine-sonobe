use crate::utils::inputs::{random_f_bigint, serialize_phrase, serialize_username};
use ark_circom::{
    circom::{r1cs_reader, R1CS},
    WitnessCalculator,
};
use ark_ff::{BigInteger, PrimeField};
use color_eyre::Result;
use num_bigint::{BigInt, Sign};
use sonobe::Error as SonobeError;
use std::{fs::File, io::BufReader, marker::PhantomData, path::PathBuf};

#[derive(Clone, Debug)]
pub struct CircomPrivateInput {
    pub phrase: Option<String>,
    pub usernames: [Option<String>; 2],
    pub auth_secrets: [Option<BigInt>; 2],
    pub chaff: bool,
}

impl CircomPrivateInput {

    /**
     * Creates empty inputs
     * 
     * @param chaff - if true, should compute random vars for chaff in circuit
     */
    pub fn empty(chaff: bool) -> Self {
        Self {
            phrase: None,
            usernames: [None, None],
            auth_secrets: [None, None],
            chaff,
        }
    }

    pub fn uninitialized(&self) -> bool {
        let not_chaff =self.phrase.is_none()
            && self.usernames.iter().all(|u| u.is_none())
            && self.auth_secrets.iter().all(|a| a.is_none());
        not_chaff && !self.chaff
    }
}

// Wrapper for circom functionalities (extract R1CS and witness)
#[derive(Clone, Debug)]
pub struct CircomWrapper<F: PrimeField> {
    r1cs_path: PathBuf,
    wc_path: PathBuf,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> CircomWrapper<F> {
    // creates a new instance of the wrapper with filepaths
    pub fn new(r1cs_path: PathBuf, wc_path: PathBuf) -> Self {
        Self {
            r1cs_path,
            wc_path,
            _marker: PhantomData,
        }
    }

    /**
     * Marshals the private inputs into the format expected by circom
     *
     * @param inputs - the private inputs
     * @return - the marshalled inputs
     */
    pub fn marshal_private_inputs(inputs: &CircomPrivateInput) -> [(String, Vec<BigInt>); 3] {
        // handle phrase presence (if not present infer chaff)
        let phrase = match &inputs.phrase {
            Some(phrase) => serialize_phrase(&phrase).unwrap().to_vec(),
            None => (0..6)
                .map(|_| random_f_bigint::<F>())
                .collect::<Vec<BigInt>>(),
        };

        // determine inputs: first step ([0] = None), Nth step ([1] = Some), and chaff ([2] = None)
        // marshal usernames
        let usernames = match inputs.usernames[0] {
            Some(_) => inputs
                .usernames
                .iter()
                .map(|u| serialize_username(&u.clone().unwrap()).unwrap())
                .collect::<Vec<BigInt>>(),
            None => match &inputs.usernames[1] {
                Some(username) => vec![BigInt::from(0), serialize_username(&username).unwrap()],
                None => vec![random_f_bigint::<F>(), random_f_bigint::<F>()],
            },
        };

        // marshal auth secrets
        let auth_sec = match inputs.auth_secrets[0] {
            Some(_) => inputs
                .auth_secrets
                .iter()
                .map(|a| a.clone().unwrap())
                .collect::<Vec<BigInt>>(),
            None => match &inputs.auth_secrets[1] {
                Some(auth_secret) => vec![BigInt::from(0), auth_secret.clone()],
                None => vec![random_f_bigint::<F>(), random_f_bigint::<F>()],
            },
        };

        // label the inputs for circom
        [
            ("phrase".to_string(), phrase),
            ("usernames".to_string(), usernames),
            ("auth_secrets".to_string(), auth_sec),
        ]
    }

    // aggregated function to obtain r1cs and witness from circom
    pub fn extract_r1cs_and_witness(
        &self,
        inputs: &[(String, Vec<BigInt>)],
    ) -> Result<(R1CS<F>, Option<Vec<F>>), SonobeError> {
        // extract R1CS
        let file = File::open(&self.r1cs_path)?;
        let reader = BufReader::new(file);
        let r1cs_file = r1cs_reader::R1CSFile::<F>::new(reader)?;
        let r1cs = r1cs_reader::R1CS::<F>::from(r1cs_file);

        // extract witness vector
        let witness_vec = self.extract_witness(inputs)?;

        Ok((r1cs, Some(witness_vec)))
    }

    pub fn extract_witness(&self, inputs: &[(String, Vec<BigInt>)]) -> Result<Vec<F>, SonobeError> {
        let witness_bigint = self.calculate_witness(inputs)?;
        witness_bigint
            .iter()
            .map(|bigint| {
                Self::num_bigint_to_ark_bigint(bigint)
                    .and_then(|ark_bigint| {
                        F::from_bigint(ark_bigint).ok_or_else(|| {
                            SonobeError::Other("Could not get F from bigint".to_string())
                        })
                    })
            })
            .collect()
    }

    pub fn calculate_witness(
        &self,
        inputs: &[(String, Vec<BigInt>)],
    ) -> Result<Vec<BigInt>, SonobeError> {
        let mut calculator = WitnessCalculator::new(&self.wc_path).map_err(|e| {
            SonobeError::WitnessCalculationError(format!(
                "Failed to create WitnessCalculator: {}",
                e
            ))
        })?;
        calculator
            .calculate_witness(inputs.iter().cloned(), true)
            .map_err(|e| {
                SonobeError::WitnessCalculationError(format!("Failed to calculate witness: {}", e))
            })
    }

    pub fn num_bigint_to_ark_bigint(value: &BigInt) -> Result<F::BigInt, SonobeError> {
        let big_uint = value
            .to_biguint()
            .ok_or_else(|| SonobeError::BigIntConversionError("BigInt is negative".to_string()))?;
        F::BigInt::try_from(big_uint).map_err(|_| {
            SonobeError::BigIntConversionError(
                "Failed to convert to Primefield::BigInt".to_string(),
            )
        })
    }

    pub fn ark_primefield_to_num_bigint(value: F) -> BigInt {
        let primefield_bigint: F::BigInt = value.into_bigint();
        let bytes = primefield_bigint.to_bytes_be();
        BigInt::from_bytes_be(Sign::Plus, &bytes)
    }
}
