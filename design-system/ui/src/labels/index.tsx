import { createContext, useContext } from "react";
import type { ReactNode } from "react";

// The words the kit's own components say without being given them: button names for screen readers and the
// few visible defaults. English here; an app in another language wraps its root in LabelsProvider.
const EN = {
  copy: (what: string) => `Copy ${what}`,
  copied: "Copied",
  remove: (what: string) => `Remove ${what}`.trim(),
  cancel: "Cancel",
  clear: "Clear",
  showOptions: "Show options",
  hiddenValue: "Hidden value",
  revealValue: "Reveal value",
  hideValue: "Hide value",
  showValue: "Show value",
  decrease: "Decrease",
  increase: "Increase",
  previousMonth: "Previous month",
  nextMonth: "Next month",
  pickDate: "Pick a date",
  pickRange: "Pick a range",
  filters: "Filters",
  filterBy: (what: string) => `Filter by ${what}`,
  selectAllRows: "Select all rows",
  selectRow: (name: string) => `Select ${name}`,
  nothingToShow: "Nothing to show.",
  actionsFor: (noun: string) => `Actions for selected ${noun}`,
  holdToConfirm: "Press and hold to confirm.",
};

export type Labels = typeof EN;

const LabelsContext = createContext<Labels>(EN);

export interface LabelsProviderProps {
  /** The strings to replace. Any left out stay in English. */
  labels: Partial<Labels>;
  /** The part of the app these strings apply to, usually all of it. */
  children: ReactNode;
}

// Replaces the kit's built-in English strings for everything inside it.
export function LabelsProvider({ labels, children }: LabelsProviderProps) {
  const outer = useContext(LabelsContext);
  return <LabelsContext.Provider value={{ ...outer, ...labels }}>{children}</LabelsContext.Provider>;
}

/** The strings in force where a kit component renders. */
export const useLabels = () => useContext(LabelsContext);
