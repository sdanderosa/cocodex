/* eslint-disable react-refresh/only-export-components -- standalone visual fixture entry */
import { createRoot } from "react-dom/client";
import "../../src/styles.css";
import "../../src/styles-cocodex.css";

function ProjectRail({ archived }: { archived: boolean }) {
  return <aside className="card cocodex-projects" style={{ width: 280, minHeight: 470 }}>
    <div className="cocodex-section-head"><span>Projects</span></div>
    <div className="cocodex-state state-connected">
      <span className="cocodex-state-dot" />
      <div><strong>Online</strong><small>127.0.0.1:10443</small></div>
    </div>
    <div className="cocodex-project-list" style={{ flex: "none" }}>
      <button type="button" className={archived ? "archived" : "active"}>
        <span aria-hidden="true">{"\u25c6"}</span>
        <span>Nocturne Launcher<small>owner {"\u00b7"} {archived ? "archived \u00b7 locked" : "locked"}</small></span>
      </button>
    </div>
    <section className="cocodex-project-lifecycle">
      <strong>Manage project</strong>
      <small>{archived
        ? "Archived projects are read-only. Restore to edit, or permanently delete after typing its exact name."
        : "Rename while active. Lock the project before archiving it."}</small>
      <div>
        {archived ? <>
          <button type="button" className="btn btn-ghost">Restore</button>
          <button type="button" className="btn btn-danger btn-ghost">Delete permanently</button>
        </> : <>
          <button type="button" className="btn btn-ghost">Rename</button>
          <button type="button" className="btn btn-ghost">Archive</button>
        </>}
      </div>
    </section>
  </aside>;
}

createRoot(document.getElementById("root")!).render(
  <main style={{ display: "flex", gap: 24, justifyContent: "center", alignItems: "flex-start", padding: "72px 24px" }}>
    <ProjectRail archived={false} />
    <ProjectRail archived />
  </main>,
);
