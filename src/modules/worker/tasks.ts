import { fail, workerError } from "@/errors";
import type { ApiClient, TaskAckPayload, WorkerTask } from "./types";

/**
 * Resolves a valid subject identifier from a worker task payload.
 * Prioritizes a non-empty string `subject_opaque_id` first, falling back to a positive integer `userId`.
 * 
 * @param task - The worker task containing payload.
 * @returns The resolved identifier as a string or a number.
 * @throws Invokes `fail()` if no valid identifier is found.
 */
export function resolveTaskSubject(task: WorkerTask): string | number {
  if (
    typeof task.payload.subject_opaque_id === "string"
    && task.payload.subject_opaque_id.trim().length > 0
  ) {
    return task.payload.subject_opaque_id.trim();
  }

  if (
    typeof task.payload.userId === "number"
    && Number.isInteger(task.payload.userId)
    && task.payload.userId > 0
  ) {
    return task.payload.userId;
  }

  fail({
    code: "TASK_PAYLOAD_INVALID",
    title: "Invalid task payload",
    detail: `Task ${task.id} requires a non-empty subject_opaque_id or numeric userId for ${task.task_type}.`,
    category: "validation",
    retryable: false,
    context: { taskId: task.id, taskType: task.task_type },
  });
}

export async function acknowledgeTask(
  apiClient: ApiClient,
  taskId: string,
  status: "completed" | "failed",
  result: TaskAckPayload
): Promise<void> {
  const acknowledged = await apiClient.ackTask(taskId, status, result);
  if (!acknowledged) {
    throw workerError({
      code: "TASK_ACK_FAILED",
      title: "Task acknowledgement failed",
      detail: `Control Plane did not acknowledge task ${taskId}.`,
      category: "network",
      retryable: true,
      context: {
        taskId,
        status,
      },
    });
  }
}
