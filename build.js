const esbuild = require('esbuild');

const isWatch = process.argv.includes('--watch');

const buildOptions = {
  entryPoints: ['./src/index.js'],
  bundle: true,
  minify: false, // <--- 修改此处：关闭压缩，保持代码可读性
  outfile: './dist/_worker.js',
  format: 'esm',
  target: 'esnext',
  external: ['cloudflare:sockets'], 
  logLevel: 'info',
};

if (isWatch) {
  esbuild.context(buildOptions).then(ctx => {
    ctx.watch();
    console.log('Watching for changes...');
  });
} else {
  esbuild.build(buildOptions).catch(() => process.exit(1));
}
