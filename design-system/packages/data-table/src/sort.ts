// Sorts rows by one value each: numbers by size, everything else as text with digits in numeric order
// ("agent-2" before "agent-10"). Rows with no value go last in both directions. Returns a new array.
export function sortRows<T>(rows: T[], value: (row: T) => unknown, dir: "asc" | "desc"): T[] {
  const sign = dir === "asc" ? 1 : -1;
  return [...rows].sort((a, b) => {
    const x = value(a),
      y = value(b);
    if (x == null || x === "") return y == null || y === "" ? 0 : 1;
    if (y == null || y === "") return -1;
    if (typeof x === "number" && typeof y === "number") return (x - y) * sign;
    return String(x).localeCompare(String(y), undefined, { numeric: true, sensitivity: "base" }) * sign;
  });
}
