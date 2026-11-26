import { Controller, Get, Inject, Param, Query, UseGuards } from "@nestjs/common";
import { OrgBindingGuard } from "../auth/org-binding.guard.js";
import { pathId, resolvePage } from "../platform/paging.js";
import { SecretsService } from "./secrets.service.js";

/** Rust `api/secrets.rs` and `api/versions.rs` read handlers. Order as in axum: org binding (401), path ids (404), query (400). */
@Controller("v1/projects/:projectId/environments/:environmentId/secrets")
@UseGuards(OrgBindingGuard)
export class SecretsController {
  constructor(@Inject(SecretsService) private readonly svc: SecretsService) {}

  @Get()
  list(@Param("projectId") projectId: string, @Param("environmentId") environmentId: string, @Query() query: unknown) {
    const ids = [pathId(projectId), pathId(environmentId)] as const;
    return this.svc.listSecrets(ids[0], ids[1], resolvePage(query));
  }

  @Get(":secretId")
  one(
    @Param("projectId") projectId: string,
    @Param("environmentId") environmentId: string,
    @Param("secretId") secretId: string,
  ) {
    return this.svc.getSecret(pathId(projectId), pathId(environmentId), pathId(secretId));
  }

  @Get(":secretId/versions")
  versions(
    @Param("projectId") projectId: string,
    @Param("environmentId") environmentId: string,
    @Param("secretId") secretId: string,
  ) {
    return this.svc.listVersions(pathId(projectId), pathId(environmentId), pathId(secretId));
  }
}
