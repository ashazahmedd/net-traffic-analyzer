/* Keep the sidebar selection aligned with anchor navigation and manual scrolling. */
(function() {
  const links=[...document.querySelectorAll('aside .nav[href^="#"]')];
  const sections=links.map(link=>({link,section:document.querySelector(link.getAttribute('href'))})).filter(item=>item.section);
  let pinned=false,settleTimer,frame;
  function activate(link) {
    links.forEach(item=>{
      const active=item===link;
      item.classList.toggle('active',active);
      if(active)item.setAttribute('aria-current','location');else item.removeAttribute('aria-current');
    });
    document.getElementById('crumb').textContent=link.querySelector('span').textContent;
  }
  function sync() {
    frame=null;
    if(pinned||document.getElementById('workspace').hidden)return;
    const atBottom=window.scrollY+window.innerHeight>=document.documentElement.scrollHeight-3 && window.scrollY>0;
    if(atBottom){activate(sections[sections.length-1].link);return;}
    const candidates=sections.map(item=>({...item,top:item.section.getBoundingClientRect().top})).filter(item=>item.top<=140).sort((a,b)=>b.top-a.top);
    activate(candidates[0]?.link || links[0]);
  }
  function schedule() {if(!frame)frame=requestAnimationFrame(sync);}
  function settle() {
    clearTimeout(settleTimer);
    settleTimer=setTimeout(()=>{pinned=false;schedule();},200);
  }
  sections.forEach(({link,section})=>link.addEventListener('click',event=>{
    if(event.button!==0||event.ctrlKey||event.metaKey||event.shiftKey||event.altKey)return;
    event.preventDefault();
    pinned=true;activate(link);
    history.replaceState(null,'',link.getAttribute('href'));
    section.scrollIntoView({block:'start'});
    clearTimeout(settleTimer);
    settleTimer=setTimeout(()=>{pinned=false;schedule();},1200);
  }));
  window.addEventListener('scroll',()=>{if(pinned)settle();else schedule();},{passive:true});
  window.addEventListener('resize',schedule);
  document.getElementById('enter').addEventListener('click',()=>{pinned=false;activate(links[0]);schedule();});
  activate(links[0]);
})();
