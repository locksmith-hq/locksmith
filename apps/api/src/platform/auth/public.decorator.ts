import { SetMetadata } from "@nestjs/common";

export const IS_PUBLIC = "auth:public";

/** Marks a route (or controller) that needs no bearer token. Everything else is guarded. */
export const Public = () => SetMetadata(IS_PUBLIC, true);
