// Runs after npm install: puts the Inter font and the app icons in place.
const fs=require('fs'),path=require('path');
const root=path.join(__dirname,'..');
const fontDir=path.join(root,'src','shared','fonts');
fs.mkdirSync(fontDir,{recursive:true});
const pkg=path.join(root,'node_modules','@fontsource-variable','inter');
fs.copyFileSync(path.join(pkg,'files','inter-latin-opsz-normal.woff2'),path.join(fontDir,'Inter-Variable.woff2'));
fs.copyFileSync(path.join(pkg,'LICENSE'),path.join(fontDir,'Inter-OFL-LICENSE.txt'));
for(const n of ['icon','tray']){
  const src=path.join(root,'build',n+'.png.b64');
  fs.writeFileSync(path.join(root,'build',n+'.png'),Buffer.from(fs.readFileSync(src,'utf8').trim(),'base64'));
}
