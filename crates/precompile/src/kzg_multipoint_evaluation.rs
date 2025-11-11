use crate::kzg_multipoint_evaluation::MULTIPOINT_EVALUATION;


//Forwarding 
pub const MULTIPOINT_EVALUATION: Precompile =
    Precompile::new(PrecompileId::KzgPointEvaluation, ADDRESS, run);
//Cast address for the implementation 0x12 was the next one available 
pub const ADDRESS: Address = crate::u64_to_address(0x12);

