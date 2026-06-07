const textDecoder = new TextDecoder();

interface GateResult {
  name: string;
  passed: boolean;
  detail: string;
}

async function readText(path: string): Promise<string> {
  const file = Bun.file(path);
  return textDecoder.decode(await file.arrayBuffer());
}

async function fileContains(path: string, pattern: RegExp): Promise<boolean> {
  return pattern.test(await readText(path));
}

async function main(): Promise<void> {
  const deploymentFiles = [
    "deploy/k8s/base/api-deployment.yaml",
    "deploy/k8s/base/worker-deployment.yaml",
    "deploy/k8s/base/web-deployment.yaml",
  ];

  const deploymentTexts = await Promise.all(deploymentFiles.map(readText));
  const deploymentText = deploymentTexts.join("\n");
  const gates: GateResult[] = [
    {
      name: "No placeholder container registry",
      passed: !deploymentText.includes("ghcr.io/your-org/"),
      detail: "Replace ghcr.io/your-org/* with the real signed image registry before release.",
    },
    {
      name: "No mutable latest tags",
      passed: !/image:\s+\S+:latest\b/.test(deploymentText),
      detail: "Use immutable tags or digests; latest is not auditable.",
    },
    {
      name: "Non-root containers",
      passed: deploymentTexts.every((text) => text.includes("runAsNonRoot: true")),
      detail: "All runtime deployments must enforce runAsNonRoot.",
    },
    {
      name: "Read-only root filesystems",
      passed: deploymentTexts.every((text) => text.includes("readOnlyRootFilesystem: true")),
      detail: "All runtime deployments must use readOnlyRootFilesystem with explicit tmp/cache volumes.",
    },
    {
      name: "Network policies present",
      passed: await fileContains("deploy/k8s/base/networkpolicies.yaml", /kind:\s+NetworkPolicy/),
      detail: "Kubernetes network policies must exist before production deployment.",
    },
    {
      name: "Prometheus alert rules present",
      passed: await fileContains("deploy/prometheus/alerts.yml", /alert:/),
      detail: "Operational alerts must be deployed with the release.",
    },
  ];

  for (const gate of gates) {
    console.log(`${gate.passed ? "PASS" : "FAIL"} ${gate.name} - ${gate.detail}`);
  }

  const failed = gates.filter((gate) => !gate.passed);
  if (failed.length > 0) {
    process.exitCode = 1;
  }
}

await main();

//Makes this file a module and allows `await import("./mega-e2e")`
export { }