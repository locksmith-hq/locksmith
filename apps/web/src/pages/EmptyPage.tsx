import { Head } from "@locksmith/ui";
import { Link } from "react-router";

/** Placeholder routed page until its content lands. */
export const EmptyPage = ({ title, note }: { title: string; note?: string }) => (
  <>
    <Head title={title} />
    {note && <p className="muted">{note} <Link to="/projects">Go to Projects</Link></p>}
  </>
);
