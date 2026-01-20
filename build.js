const esbuild = require('esbuild');
const { cleanFile } = require('./cleaner.js'); // 引入清理脚本

const isWatch = process.argv.includes('--watch');

// 定义 Cleaner 插件
const cleanerPlugin = {
  name: 'auto-cleaner',
  setup(build) {
    // 在构建结束 (onEnd) 时执行清理
    build.onEnd(result => {
      if (result.errors.length > 0) {
        console.log('[Cleaner] Build failed, skipping clean.');
        return;
      }
      // 这里的路径应与 outfile 保持一致
      cleanFile('./dist/_worker.js');
    });
  },
};

const buildOptions = {
  entryPoints: ['./src/index.js'],
  bundle: true,
  minify: false, // 保持关闭，由 cleaner 处理注释
  outfile: './dist/_worker.js',
  format: 'esm',
  target: 'esnext',
  external: ['cloudflare:sockets'], 
  logLevel: 'info',
  plugins: [cleanerPlugin] // 注册插件
};

if (isWatch) {
  esbuild.context(buildOptions).then(ctx => {
    ctx.watch();
    console.log('Watching for changes...');
  });
} else {
  esbuild.build(buildOptions).catch(() => process.exit(1));
}
