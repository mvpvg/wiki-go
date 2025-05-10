// Task List Live Editing
// This script enables live checkbox toggling for admins & editors.
// It relies on the existing /api/source and /api/save endpoints.
(function () {
  document.addEventListener('DOMContentLoaded', () => {
    const role = document.querySelector('meta[name="user-role"]')?.content || 'viewer';
    const docPath = (document.querySelector('meta[name="doc-path"]')?.content || '').replace(/^\//, '');

    // Abort if no permissions or preview contexts
    if (!(role === 'admin' || role === 'editor')) return;
    if (document.body.classList.contains('editing')) return; // edit mode
    if (document.querySelector('.version-content')) return;  // version preview

    const container = document.querySelector('.markdown-content');
    if (!container) return;

    // Enable checkboxes (Goldmark renders them disabled by default) and cache list
    const allCheckboxes = [...container.querySelectorAll('input[type="checkbox"]')];
    allCheckboxes.forEach((cb, idx) => { cb.disabled = false; cb.dataset.cbIndex = idx; });

    // Helper to enable / disable all list checkboxes
    const toggleAll = (disabled) => { allCheckboxes.forEach(cb => cb.disabled = disabled); };

    // Ensure every task-list <li> has a persistent .save-state span
    container.querySelectorAll('li').forEach(li => {
      if (!li.querySelector('input[type="checkbox"]')) return; // not a task item
      if (!li.querySelector('.save-state')) {
        const span = document.createElement('span');
        span.className = 'save-state';
        const firstUL = li.querySelector('ul');
        if (firstUL) {
          li.insertBefore(span, firstUL);
        } else {
          li.appendChild(span);
        }
      }
    });

    const showState = (li, text, cssClass) => {
      const s = li.querySelector('.save-state');
      if (!s) return;
      s.textContent = text;
      s.classList.remove('saved','error');
      if(cssClass) s.classList.add(cssClass); else s.classList.remove('saved','error');
    };

    const hideStateAfter = (li, delay=3000) => {
      const s = li.querySelector('.save-state');
      if (!s) return;
      setTimeout(()=>{ s.textContent=''; }, delay);
    };

    container.addEventListener('click', async (e) => {
      const target = e.target;
      if (!(target instanceof HTMLInputElement) || target.type !== 'checkbox') return;
      e.preventDefault();
      const li = target.closest('li');
      if (!li) return;

      showState(li,'saving…');

      // Disable all checkboxes during save
      toggleAll(true);

      try {
        // 1. Fetch current markdown
        const srcResp = await fetch(`/api/source/${docPath}`);
        if (!srcResp.ok) throw new Error('source fetch failed');
        const markdown = await srcResp.text();

        // 2. Build updated markdown by toggling the first matching task line.
        const lines = markdown.split(/\r?\n/);
        const desiredChecked = !target.checked;
        // Determine checkbox index among all rendered checkboxes
        const cbIndex = Number(target.dataset.cbIndex);

        let currentIdx = -1;
        const updatedLines = lines.map((line) => {
          const match = line.match(/^(\s*[-*+]\s+)\[(.| )\]\s+(.*)$/);
          if (!match) return line; // not a task list line
          currentIdx += 1;
          if (currentIdx === cbIndex) {
            const [, prefix, , restText] = match;
            const newMark = desiredChecked ? 'x' : ' ';
            return `${prefix}[${newMark}] ${restText}`;
          }
          return line;
        });
        if (cbIndex > currentIdx) throw new Error('checkbox index exceeds markdown task list count');

        // 3. Save updated markdown
        const saveResp = await fetch(`/api/save/${docPath}`, {
          method: 'POST',
          headers: { 'Content-Type': 'text/markdown' },
          body: updatedLines.join('\n'),
        });
        if (!saveResp.ok) throw new Error('save failed');

        // 4. Update UI checkbox state
        target.checked = desiredChecked;
        showState(li,'saved','saved');
        hideStateAfter(li,3000);
      } catch (err) {
        console.error(err);
        showState(li,'error','error');
      } finally {
        toggleAll(false);
      }
    });
  });
})();