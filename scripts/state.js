// state.js
const LSKEY = 'pool-olympiques-2026-state';

export const State = {
  load(){
    try{
      const raw = localStorage.getItem(LSKEY);
      if(raw){ return JSON.parse(raw); }
    }catch(e){ console.warn('State load error', e); }
    return {
      scoring: { goal: 1, assist: 1, goalie_win: 2, goalie_otl: 1, shutout: 3 },
      boxRulesEnabled: true,
      players: [],
      poolers: [],
      stats: {}, // { player: { 'YYYY-MM-DD': {goals,assists,win,otl,so} } }
      lastUpdate: null,
    };
  },
  save(s){ localStorage.setItem(LSKEY, JSON.stringify(s)); },
  resetScoring(s){ s.scoring = { goal: 1, assist: 1, goalie_win: 2, goalie_otl: 1, shutout: 3 }; },
};
