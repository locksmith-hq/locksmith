import { Module } from "@nestjs/common";
import { APP_FILTER } from "@nestjs/core";
import { ProblemFilter } from "./problem.filter.js";

@Module({ providers: [{ provide: APP_FILTER, useClass: ProblemFilter }] })
export class ProblemModule {}
