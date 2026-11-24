// Paths with no scenario yet, each with the reason it is excluded. A scenario file that covers a
// path must delete its row here: the coverage test fails on a row that is already covered.
export const EXCLUDED: Record<string, string> = {};
