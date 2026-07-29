import { projectKeyEnvelopeSchema, type ProjectKeyEnvelope } from "./project-encryption";

export interface ProjectCreationSigningInput {
  projectId: string;
  name: string;
  ownerDeviceId: string;
  envelopes: readonly ProjectKeyEnvelope[];
}

function lengthPrefix(value: string): Buffer {
  const bytes = Buffer.from(value, "utf8");
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

/**
 * Bind project identity, display metadata, creator, membership, and every
 * signed epoch-1 key envelope into one creator signature. Recipients are
 * sorted so transport order cannot change the signed meaning.
 */
export function projectCreationSigningTranscript(input: ProjectCreationSigningInput): Buffer {
  const envelopes = input.envelopes
    .map(value => projectKeyEnvelopeSchema.parse(value))
    .sort((left, right) => left.recipientDeviceId.localeCompare(right.recipientDeviceId));
  const fields = [
    "1",
    input.projectId,
    input.name.trim(),
    input.ownerDeviceId,
    String(envelopes.length),
  ];
  for (const envelope of envelopes) {
    fields.push(
      envelope.projectId,
      String(envelope.keyEpoch),
      envelope.recipientDeviceId,
      envelope.senderDeviceId,
      envelope.senderPublicKeyPem,
      envelope.sealedProjectKey,
      envelope.signature,
    );
  }
  return Buffer.concat([
    Buffer.from("COCODEX-PROJECT-CREATE\u0000", "utf8"),
    ...fields.map(lengthPrefix),
  ]);
}
