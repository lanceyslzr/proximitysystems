'use strict';
// Strip ONLY comments from JavaScript, preserving string and template contents,
// because class names live inside strings but prose also lives inside comments.
// Regex literals must not be mistaken for comments or division.
function stripComments(text){
  const n=text.length; let i=0, out='', lastSig='';
  const Q=String.fromCharCode(39), BT=String.fromCharCode(96);
  while(i<n){
    const c=text[i], c2=text[i+1];
    if(c==='/'&&c2==='/'){ while(i<n&&text[i]!=='\n') i++; out+=' '; continue; }
    if(c==='/'&&c2==='*'){ i+=2; while(i<n&&!(text[i]==='*'&&text[i+1]==='/')) i++; i+=2; out+=' '; continue; }
    if(c==='"'||c===Q){
      const q=c; out+=c; i++;
      while(i<n){ if(text[i]==='\\'){ out+=text[i]+(text[i+1]||''); i+=2; continue; } if(text[i]===q){ out+=q; i++; break; } out+=text[i]; i++; }
      lastSig=q; continue;
    }
    if(c===BT){
      out+=c; i++;
      while(i<n){ if(text[i]==='\\'){ out+=text[i]+(text[i+1]||''); i+=2; continue; } if(text[i]===BT){ out+=BT; i++; break; } out+=text[i]; i++; }
      lastSig=BT; continue;
    }
    if(c==='/'&&/[=(,:[!&|?{};+\-*%~^<>]|^$/.test(lastSig)){
      // regex literal
      out+=c; i++;
      let inClass=false;
      while(i<n){
        const d=text[i];
        if(d==='\\'){ out+=d+(text[i+1]||''); i+=2; continue; }
        if(d==='['){ inClass=true; }
        else if(d===']'){ inClass=false; }
        else if(d==='/'&&!inClass){ out+=d; i++; break; }
        else if(d==='\n'){ break; }
        out+=d; i++;
      }
      lastSig='/'; continue;
    }
    out+=c;
    if(!/\s/.test(c)) lastSig=c;
    i++;
  }
  return out;
}
module.exports={stripComments};

if(require.main===module){
  const Q=String.fromCharCode(39), BT=String.fromCharCode(96);
  const cases=[
    ['// comment with active\nvar a=1;', 'active', 0, 'line comment removed'],
    ['/* block active */var a=1;', 'active', 0, 'block comment removed'],
    ['var s="keep active here";', 'active', 1, 'string content preserved'],
    ['el.classList.add('+Q+'show'+Q+');', 'show', 1, 'class string preserved'],
    ['var r=/active/g;', 'active', 1, 'regex body preserved'],
    ['var u="http://x.com/active";', 'active', 1, 'url inside string not a comment'],
    ['var t='+BT+'tmpl active'+BT+';', 'active', 1, 'template preserved'],
    ['var a=1/2; // active', 'active', 0, 'division then comment'],
  ];
  let pass=0;
  console.log('COMMENT STRIPPER TRAPS');
  for(const [src,tok,want,label] of cases){
    const got=(stripComments(src).match(new RegExp(tok,'g'))||[]).length;
    const ok=(want===0? got===0 : got>=1);
    if(ok)pass++;
    console.log('  '+(ok?'ok  ':'FAIL')+'  '+label.padEnd(34)+'found '+got+'  want '+(want===0?'0':'>=1'));
  }
  console.log('  traps passed '+pass+' of '+cases.length);
  if(pass!==cases.length) process.exit(1);
}
