// Every mockup page that is not built into Console.tsx, keyed "<space>/<tab>" (see `spaces` in ../data.ts).
import type { Pages } from "../kit";
import { pages as gateway } from "./gateway";
import { pages as lobby } from "./lobby";
import { pages as lifecycle } from "./lifecycle";
import { pages as access } from "./access";
import { pages as certs } from "./certs";
import { pages as kms } from "./kms";
import { pages as broker } from "./broker";
import { pages as security } from "./security";
import { pages as platform } from "./platform";

export const PAGES: Pages = { ...gateway, ...lobby, ...lifecycle, ...access, ...certs, ...kms, ...broker, ...security, ...platform };
