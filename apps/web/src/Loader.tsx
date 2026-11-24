import { VaultMark } from "@locksmith/ui";

/** The mockup's loader: the vault dial turning and throwing its bolts. `fill` centers it on the whole page. */
export function Loader({ label = "Loading", fill = false }: { label?: string; fill?: boolean }) {
  return (
    <div className={fill ? "loader loader-fill" : "loader"} role="status">
      <span className="logo">
        <VaultMark small size={42} />
      </span>
      <span className="sr-only">{label}</span>
    </div>
  );
}
