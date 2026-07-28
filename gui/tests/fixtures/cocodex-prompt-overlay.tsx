import { createRoot } from "react-dom/client";
import { CollaborativePromptEditor } from "../../src/components/CollaborativePromptEditor";
import "../../src/styles.css";
import "../../src/styles-cocodex.css";

const prompt = "@Lucas review the authentication flow and document the refresh-token race.\n@Angela prepare regression coverage from Lucas's finding.";

createRoot(document.getElementById("root")!).render(
  <main style={{ width: 760, margin: "90px auto", padding: 24 }}>
    <section className="card" style={{ overflow: "visible" }}>
      <label className="cocodex-shared-prompt">
        <span><strong>Shared prompt</strong><small>Live collaborative draft</small></span>
        <CollaborativePromptEditor className="input" value={prompt} readOnly rows={5}
          aria-label="Shared prompt"
          remotePresence={[
            {
              deviceId: "kai-fixture-device",
              displayName: "Kai",
              typing: true,
              caret: { anchor: 7, head: 46 },
            },
            {
              deviceId: "stephen-fixture-device",
              displayName: "Stephen",
              typing: false,
              caret: { anchor: 96, head: 96 },
            },
          ]} />
        <div className="cocodex-prompt-presence">
          <span className="cocodex-prompt-presence-member"><i className="typing" /><strong>Kai</strong><small>typing…</small></span>
          <span className="cocodex-prompt-presence-member"><i className="caret" /><strong>Stephen</strong><small>caret 96</small></span>
        </div>
      </label>
    </section>
  </main>,
);
