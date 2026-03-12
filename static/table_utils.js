(function(){
  const DEFAULT_DEBOUNCE = 140;
  const tableHelpers = new WeakMap();

  function parseNumber(value){
    const match = value.match(/[-+]?\d+(\.\d+)?/);
    if(!match) return null;
    const num = parseFloat(match[0]);
    return Number.isNaN(num) ? null : num;
  }

  function getHeaderRow(thead){
    if(!thead) return null;
    return thead.querySelector('tr.header') || thead.querySelector('tr');
  }

  function ensureFilterRow(thead, headerCells, noFilters){
    if(noFilters) return null;
    let filterRow = thead.querySelector('tr.table-filters');
    if(filterRow) return filterRow;
    filterRow = document.createElement('tr');
    filterRow.className = 'table-filters';
    headerCells.forEach((th, idx) => {
      const cell = document.createElement('th');
      const type = (th.dataset && th.dataset.type) ? th.dataset.type : 'text';
      const label = (th.textContent || '').trim();
      if(type === 'none'){
        // action / checkbox columns — no filter control
      } else if(type === 'date'){
        const input = document.createElement('input');
        input.type = 'text';
        input.className = 'table-filter table-filter-date';
        input.dataset.col = String(idx);
        input.placeholder = label || 'Date';
        input.setAttribute('aria-label', label ? `${label} date range` : 'Date range');
        input.readOnly = true;
        cell.appendChild(input);
      } else if(type === 'select'){
        const sel = document.createElement('select');
        sel.className = 'table-filter';
        sel.dataset.col = String(idx);
        sel.setAttribute('aria-label', `Filter ${label}`);
        const allOpt = document.createElement('option');
        allOpt.value = '';
        allOpt.textContent = 'All';
        sel.appendChild(allOpt);
        const rawOpts = (th.dataset && th.dataset.options) ? th.dataset.options : '';
        if(rawOpts){
          try{
            JSON.parse(rawOpts).forEach(o => {
              const opt = document.createElement('option');
              opt.value = String(o).toLowerCase();
              opt.textContent = String(o);
              sel.appendChild(opt);
            });
          }catch(e){}
        }
        cell.appendChild(sel);
      } else {
        const input = document.createElement('input');
        input.className = 'table-filter';
        input.dataset.col = String(idx);
        const placeholder = label ? `Filter ${label}` : 'Filter';
        input.placeholder = placeholder;
        input.setAttribute('aria-label', placeholder);
        cell.appendChild(input);
      }
      filterRow.appendChild(cell);
    });
    thead.appendChild(filterRow);
    if(typeof flatpickr !== 'undefined'){
      filterRow.querySelectorAll('.table-filter-date').forEach(inp => {
        flatpickr(inp, { mode: 'range', dateFormat: 'Y-m-d', disableMobile: true });
      });
    }
    return filterRow;
  }

  function initTable(table, opts = {}){
    if(!table) return null;
    const existing = tableHelpers.get(table);
    if(existing) return existing;

    const tbody = table.querySelector('tbody');
    const thead = table.querySelector('thead');
    if(!tbody || !thead) return null;

    const headerRow = getHeaderRow(thead);
    if(!headerRow) return null;
    headerRow.classList.add('header');
    const headerCells = Array.from(headerRow.querySelectorAll('th'));
    if(!headerCells.length) return null;
    const noFilters = table.hasAttribute('data-no-filters');
    const filterRow = ensureFilterRow(thead, headerCells, noFilters);
    const filterInputs = filterRow ? Array.from(filterRow.querySelectorAll('.table-filter')) : [];
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const rowCache = new Map();

    rows.forEach(row => {
      const values = Array.from(row.children).map(cell => (cell.textContent || '').trim());
      rowCache.set(row, {
        raw: values,
        lower: values.map(v => v.toLowerCase()),
        num: Array(values.length).fill(undefined),
        date: Array(values.length).fill(undefined),
        dateKey: Array(values.length).fill(undefined)
      });
    });

    let sortState = { idx: null, dir: 'asc' };
    let activeFilters = [];
    let filterTimer = null;

    function getRaw(row, idx){
      return rowCache.get(row)?.raw[idx] || '';
    }

    function getLower(row, idx){
      return rowCache.get(row)?.lower[idx] || '';
    }

    function getNum(row, idx){
      const cache = rowCache.get(row);
      if(!cache) return null;
      if(cache.num[idx] === undefined){
        cache.num[idx] = parseNumber(cache.raw[idx] || '');
      }
      return cache.num[idx];
    }

    function getDate(row, idx){
      const cache = rowCache.get(row);
      if(!cache) return 0;
      if(cache.date[idx] === undefined){
        const value = cache.raw[idx] || '';
        const parsed = Date.parse(value);
        cache.date[idx] = Number.isNaN(parsed) ? 0 : parsed;
      }
      return cache.date[idx];
    }

    function getDateKey(row, idx){
      const cache = rowCache.get(row);
      if(!cache) return '';
      if(cache.dateKey[idx] === undefined){
        const value = (cache.raw[idx] || '').trim();
        const m = value.match(/^(\d{4}-\d{2}-\d{2})/);
        if(m){
          cache.dateKey[idx] = m[1];
        }else{
          const parsed = Date.parse(value);
          if(Number.isNaN(parsed)){
            cache.dateKey[idx] = '';
          }else{
            cache.dateKey[idx] = new Date(parsed).toISOString().slice(0, 10);
          }
        }
      }
      return cache.dateKey[idx];
    }

    function compareValues(rowA, rowB, idx, type){
      if(type === 'number'){
        const na = getNum(rowA, idx);
        const nb = getNum(rowB, idx);
        if(na === null && nb === null) return 0;
        if(na === null) return 1;
        if(nb === null) return -1;
        return na - nb;
      }
      if(type === 'date'){
        return getDate(rowA, idx) - getDate(rowB, idx);
      }
      const a = getRaw(rowA, idx);
      const b = getRaw(rowB, idx);
      return a.localeCompare(b, undefined, {numeric:true, sensitivity:'base'});
    }

    function applySort(){
      if(sortState.idx === null) return;
      const idx = sortState.idx;
      const type = headerCells[idx]?.dataset?.type || 'text';
      rows.sort((ra, rb) => {
        const cmp = compareValues(ra, rb, idx, type);
        return sortState.dir === 'asc' ? cmp : -cmp;
      });
      rows.forEach(r => tbody.appendChild(r));
      headerCells.forEach(h => h.removeAttribute('data-sort-dir'));
      headerCells[idx]?.setAttribute('data-sort-dir', sortState.dir);
    }

    function collectFilters(){
      activeFilters = [];
      filterInputs.forEach(input => {
        const idx = parseInt(input.dataset.col, 10);
        const type = headerCells[idx]?.dataset?.type || 'text';
        const val = (input.value || '').trim();
        if(!val) return;
        if(type === 'date'){
          let from = '', to = '';
          if(val.includes(' to ')){
            const parts = val.split(' to ');
            from = parts[0].trim();
            to   = parts[1].trim();
          } else {
            from = to = val;
          }
          activeFilters.push({ idx, type: 'date', from, to });
          return;
        }
        activeFilters.push({ idx, type, value: val.toLowerCase() });
      });
    }

    function matchesFilter(row, filter){
      const { idx, type } = filter;
      if(type === 'number'){
        const m = filter.value.match(/^(<=|>=|<|>|=)?\s*([-+]?\d+(\.\d+)?)/);
        if(m){
          const op = m[1] || '=';
          const num = parseFloat(m[2]);
          const val = getNum(row, idx);
          if(val === null) return false;
          if(op === '<') return val < num;
          if(op === '>') return val > num;
          if(op === '<=') return val <= num;
          if(op === '>=') return val >= num;
          return val === num;
        }
      }
      if(type === 'date'){
        const key = getDateKey(row, idx);
        if(filter.from && key < filter.from) return false;
        if(filter.to   && key > filter.to)   return false;
        return true;
      }
      if(type === 'select'){
        return getLower(row, idx) === filter.value;
      }
      return getLower(row, idx).includes(filter.value);
    }

    function applyFilters(){
      if(activeFilters.length === 0){
        rows.forEach(r => { r.style.display = ''; });
        return;
      }
      rows.forEach(row => {
        let visible = true;
        for(const f of activeFilters){
          if(!matchesFilter(row, f)){
            visible = false;
            break;
          }
        }
        row.style.display = visible ? '' : 'none';
      });
    }

    function scheduleFilter(){
      if(filterTimer){ clearTimeout(filterTimer); }
      filterTimer = setTimeout(() => {
        filterTimer = null;
        collectFilters();
        requestAnimationFrame(applyFilters);
      }, opts.debounceMs || DEFAULT_DEBOUNCE);
    }

    headerCells.forEach((th, idx) => {
      th.addEventListener('click', () => {
        const isSame = sortState.idx === idx;
        sortState = { idx, dir: isSame && sortState.dir === 'asc' ? 'desc' : 'asc' };
        applySort();
      });
    });

    filterInputs.forEach(input => {
      input.addEventListener('input', scheduleFilter);
      input.addEventListener('change', scheduleFilter);
    });

    const helper = {
      isActive: () => {
        const hasFilters = filterInputs.some(i => i.value.trim() !== '');
        return hasFilters || sortState.idx !== null;
      },
      apply: () => { collectFilters(); applyFilters(); applySort(); }
    };
    tableHelpers.set(table, helper);
    return helper;
  }

  function initAll(selector = '.table-sortable'){
    const tables = Array.from(document.querySelectorAll(selector));
    return tables.map(t => initTable(t)).filter(Boolean);
  }

  window.TableFilterSort = { initTable, initAll };

  if(document.readyState === 'loading'){
    document.addEventListener('DOMContentLoaded', () => initAll());
  }else{
    initAll();
  }
})();
