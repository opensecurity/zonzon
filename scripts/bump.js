import { readFile, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';

const WORKSPACES = [
  '.',
  'packages/core',
  'packages/control-plane',
  'packages/cli'
];

const MONOREPO_PREFIX = '@opensecurity/';

async function bumpVersions() {
  const bumpType = process.argv[2] || 'patch'; // major, minor, patch
  if (!['major', 'minor', 'patch'].includes(bumpType)) {
    console.error('❌ Invalid bump type. Use: major, minor, or patch.');
    process.exit(1);
  }

  const rootPkgPath = resolve(join('.', 'package.json'));
  const rootPkg = JSON.parse(await readFile(rootPkgPath, 'utf8'));
  const currentVersion = rootPkg.version;

  const [major, minor, patch] = currentVersion.split('.').map(Number);
  let newVersion;
  
  if (bumpType === 'major') newVersion = `${major + 1}.0.0`;
  else if (bumpType === 'minor') newVersion = `${major}.${minor + 1}.0`;
  else newVersion = `${major}.${minor}.${patch + 1}`;

  console.log(`🚀 Bumping workspace from v${currentVersion} to v${newVersion} (${bumpType})`);

  for (const workspace of WORKSPACES) {
    const pkgPath = resolve(join(workspace, 'package.json'));
    try {
      const pkgRaw = await readFile(pkgPath, 'utf8');
      const pkg = JSON.parse(pkgRaw);

      pkg.version = newVersion;

      if (pkg.dependencies) updateInterDeps(pkg.dependencies, newVersion);
      if (pkg.devDependencies) updateInterDeps(pkg.devDependencies, newVersion);
      if (pkg.peerDependencies) updateInterDeps(pkg.peerDependencies, newVersion);

      await writeFile(pkgPath, JSON.stringify(pkg, null, 2) + '\n', 'utf8');
      console.log(`✅ Updated ${pkg.name}`);
      
    } catch (err) {
      console.error(`⚠️  Failed to update ${workspace}/package.json:`, err.message);
    }
  }

  console.log(`\n🎉 All packages bumped to v${newVersion}. Run 'npm install' to update your lockfile.`);
}

function updateInterDeps(dependencies, newVersion) {
  for (const dep in dependencies) {
    if (dep.startsWith(MONOREPO_PREFIX)) {
      const prefix = dependencies[dep].match(/^[~^]/) ? dependencies[dep][0] : '^';
      dependencies[dep] = `${prefix}${newVersion}`;
    }
  }
}

bumpVersions();