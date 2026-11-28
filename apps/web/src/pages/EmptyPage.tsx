import { PageHeader } from "@locksmith-hq/ui/page-header";
import { Link } from "react-router";

/** Placeholder routed page until its content lands. */
export const EmptyPage = ({ title, note }: { title: string; note?: string }) => (
  <>
    <PageHeader title={title} />
    {note && (
      <p className="text-muted-foreground [&_a]:underline [&_a]:underline-offset-3">
        {note} <Link to="/projects">Go to Projects</Link>
      </p>
    )}
  </>
);
