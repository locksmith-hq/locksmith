// A workspace's icon: its uploaded image (the company logo, say), else the first letter of its name.
import type { Workspace } from "./data";

export const WorkspaceIcon = ({ w }: { w: Pick<Workspace, "name" | "icon"> }) => (
  <span className="av">{w.icon ? <img src={w.icon} alt="" /> : w.name[0]}</span>
);
