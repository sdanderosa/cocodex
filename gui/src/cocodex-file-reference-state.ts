interface ReferenceArtifactCandidate {
  id: string;
  authorDeviceId: string;
}

export function retainLocalReferenceArtifactId(
  selectedId: string,
  artifacts: ReferenceArtifactCandidate[],
  localDeviceId: string | undefined,
): string {
  return artifacts.some(artifact =>
    artifact.id === selectedId && artifact.authorDeviceId === localDeviceId) ? selectedId : "";
}

export type ReferenceArtifactSelectionAction =
  | { type: "select"; artifactId: string }
  | { type: "project-changed" }
  | {
    type: "artifacts-replaced";
    artifacts: ReferenceArtifactCandidate[];
    localDeviceId: string | undefined;
  };

export function referenceArtifactSelectionReducer(
  selectedId: string,
  action: ReferenceArtifactSelectionAction,
): string {
  if (action.type === "select") return action.artifactId;
  if (action.type === "project-changed") return "";
  return retainLocalReferenceArtifactId(selectedId, action.artifacts, action.localDeviceId);
}
