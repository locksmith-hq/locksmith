import { ArgumentsHost, Catch, ExceptionFilter, Logger } from "@nestjs/common";
import type { Response } from "express";
import { HttpException } from "@nestjs/common";
import { PROBLEM_JSON, toProblem } from "./problem.js";

/** Global filter: every error leaves as application/problem+json and never echoes the request. */
@Catch()
export class ProblemFilter implements ExceptionFilter {
  private readonly log = new Logger("problem");

  catch(e: unknown, host: ArgumentsHost) {
    const body = toProblem(e);
    // Log the class only: the message may carry request data.
    if (body.status >= 500) this.log.error({ event: "problem.internal", error: e instanceof HttpException ? "http" : (e as Error)?.name });
    const res = host.switchToHttp().getResponse<Response>();
    res.status(body.status).setHeader("Content-Type", PROBLEM_JSON).end(JSON.stringify(body));
  }
}
