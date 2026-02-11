// csv.js
export const CSV = {
  parse(text){
    const rows = [];
    let cur = '', row = [], inQuotes = false;
    for(let i=0;i<text.length;i++){
      const c = text[i];
      if(inQuotes){
        if(c==='"'){
          if(text[i+1]==='"'){ cur+='"'; i++; } else { inQuotes=false; }
        } else { cur+=c; }
      } else {
        if(c==='"'){ inQuotes=true; }
        else if(c===','){ row.push(cur); cur=''; }
        else if(c==='\n'){ row.push(cur); rows.push(row); row=[]; cur=''; }
        else if(c==='\r'){ }
        else { cur+=c; }
      }
    }
    if(cur.length>0 || row.length>0){ row.push(cur); rows.push(row); }
    return rows.filter(r=>r.length && r.some(x=>x!==''));
  },
  escape(val){
    const s = String(val||'');
    if(/[",\n]/.test(s)) return '"'+s.replaceAll('"','""')+'"';
    return s;
  }
};
