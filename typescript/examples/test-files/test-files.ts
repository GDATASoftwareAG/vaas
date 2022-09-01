import { argv, exit } from "process";
import { promises as fs } from "fs";
import createVaas from "../../tests/createVaas";

async function main() {
  if (argv.length < 3) {
    console.log("Usage: ts-node test-files.ts [FILE]");
    exit(1);
  }

  const vaas = await createVaas();

  for (const path of argv.slice(2)) {
    console.log(`Testing ${path}`);
    const f = await fs.open(path, "r");
    try {
      const verdict = await vaas.forFile(await f.readFile());
      console.log(`Tested ${path}: Verdict ${verdict}`);
    } finally {
      f.close();
    }
  }

  vaas.close();
}

main().catch((e) => console.error(e));
