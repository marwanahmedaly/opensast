from aisast.context.evidence import EvidenceGate, Validation
from aisast.models import EvidencePacket, VerificationResult

def validate_result(packet: EvidencePacket, result: VerificationResult) -> Validation:
    return EvidenceGate().validate(packet, result)
