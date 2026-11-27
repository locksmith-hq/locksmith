import { ProblemException } from "../platform/problem.js";
import { validateName } from "../orgs/orgs.service.js";
import type { Patch } from "./projects.schemas.js";

const MAX_DESCRIPTION_CHARS = 4096;

/** Rust `validate_description`. */
export function validateDescription(description: string): void {
  if ([...description].length > MAX_DESCRIPTION_CHARS)
    throw new ProblemException("validation", `\`description\` must be at most ${MAX_DESCRIPTION_CHARS} characters`);
}

/** Rust `Patch::validate`: at least one field, each valid. */
export function validatePatch(p: Patch): void {
  if (p.name == null && p.description == null)
    throw new ProblemException("validation", "provide `name` and/or `description` to change");
  if (p.name != null) validateName(p.name);
  if (p.description != null) validateDescription(p.description);
}
