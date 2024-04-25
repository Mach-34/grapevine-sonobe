use ark_pallas::{constraints::GVar, Fr, Projective};
use ark_vesta::{constraints::GVar as GVar2, Projective as Projective2};

use sonobe::{
    commitment::{pedersen::Pedersen, CommitmentScheme},
    folding::nova::{get_r1cs, ProverParams, VerifierParams},
    frontend::FCircuit,
    transcript::poseidon::poseidon_test_config
};

pub fn test_nova_setup<FC: FCircuit<Fr>>(
    f_circuit: FC
) -> (
    ProverParams<Projective, Projective2, Pedersen<Projective>, Pedersen<Projective2>>,
    VerifierParams<Projective, Projective2>
) {
    let mut rng = ark_std::test_rng();
    let poseidon_config = poseidon_test_config::<Fr>();

    // get CM & CF_CM len
    let (r1cs, cf_r1cs) = get_r1cs::<Projective, GVar, Projective2, GVar2, FC>(
        &poseidon_config,
        f_circuit,
    ).unwrap();
    let cf_len = r1cs.A.n_rows;
    let cf_cf_len = cf_r1cs.A.n_rows;

    let (pedersen_params, _) = Pedersen::<Projective>::setup(&mut rng, cf_len).unwrap();
    let (cf_pedersen_params, _) = Pedersen::<Projective2>::setup(&mut rng, cf_cf_len).unwrap();

    let prover_params = 
        ProverParams::<Projective, Projective2, Pedersen<Projective>, Pedersen<Projective2>>{
           poseidon_config: poseidon_config.clone(),
           cs_params: pedersen_params,
           cf_cs_params: cf_pedersen_params
        };
    
    let verifier_params = VerifierParams::<Projective, Projective2>{
        poseidon_config: poseidon_config.clone(),
        r1cs,
        cf_r1cs
    };

    (prover_params, verifier_params)
}