import { rm } from "node:fs/promises";

// Clean dist folder
await rm("./dist", { recursive: true, force: true });

// Build ESM
const esmResult = await Bun.build({
	entrypoints: ["./src/index.ts"],
	outdir: "./dist",
	format: "esm",
	target: "browser",
	minify: true,
	sourcemap: "external",
	external: ["@bsv/sdk"],
	naming: "[dir]/index.module.[ext]",
});

if (!esmResult.success) {
	console.error("ESM build failed:");
	for (const log of esmResult.logs) {
		console.error(log);
	}
	process.exit(1);
}

// Build CJS
const cjsResult = await Bun.build({
	entrypoints: ["./src/index.ts"],
	outdir: "./dist",
	format: "cjs",
	target: "browser",
	minify: true,
	sourcemap: "external",
	external: ["@bsv/sdk"],
	naming: "[dir]/index.[ext]",
});

if (!cjsResult.success) {
	console.error("CJS build failed:");
	for (const log of cjsResult.logs) {
		console.error(log);
	}
	process.exit(1);
}

// Rename CJS output from .js to .cjs
const cjsFile = Bun.file("./dist/index.js");
if (await cjsFile.exists()) {
	await Bun.write("./dist/index.cjs", cjsFile);
	await rm("./dist/index.js");
	// Also rename sourcemap
	const cjsMapFile = Bun.file("./dist/index.js.map");
	if (await cjsMapFile.exists()) {
		await Bun.write("./dist/index.cjs.map", cjsMapFile);
		await rm("./dist/index.js.map");
	}
}

console.log("Build complete!");
console.log("  - dist/index.module.js (ESM)");
console.log("  - dist/index.cjs (CommonJS)");
console.log("\nRun 'bun run types' to generate TypeScript declarations.");
