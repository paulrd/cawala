<script>
  /**
   * DataTable — sortable table with row-click and custom cell renderers.
   * Horizontal scroll on mobile.
   *
   * Columns: { key, label, sortable?, align?, mono?, render?(value, row, index) }
   * The render function receives (value, row, index) and returns an HTML string
   * or template result. If not provided, value is rendered as-is.
   *
   * @param {Array<object>} columns
   * @param {Array<object>} rows
   * @param {function} [onRowClick] - (row, event) => void
   * @param {string} [emptyMessage='No data']
   * @param {string} [sortKey]
   * @param {string} [sortDir='asc']
   * @param {function} [onSort] - (key, dir) => void
   */
  let {
    columns = [],
    rows = [],
    onRowClick,
    emptyMessage = 'No data',
    sortKey = '',
    sortDir = 'asc',
    onSort,
  } = $props();

  function handleSort(key) {
    if (!onSort) return;
    const newDir = sortKey === key && sortDir === 'asc' ? 'desc' : 'asc';
    onSort(key, newDir);
  }

  function handleRowClick(row, e) {
    if (onRowClick) onRowClick(row, e);
  }

  function handleKeydown(row, e) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      onRowClick(row, e);
    }
  }
</script>

<div class="table-wrap">
  <table>
    <thead>
      <tr>
        {#each columns as col (col.key)}
          <th
            class:mono={col.mono}
            class:num={col.align === 'right'}
            class:sortable={col.sortable}
            class:active={sortKey === col.key}
            onclick={() => col.sortable && handleSort(col.key)}
            onkeydown={(e) => col.sortable && e.key === 'Enter' && handleSort(col.key)}
            role={col.sortable ? 'button' : undefined}
            tabindex={col.sortable ? 0 : undefined}
            aria-sort={sortKey === col.key ? (sortDir === 'asc' ? 'ascending' : 'descending') : undefined}
          >
            {col.label}
            {#if sortKey === col.key}
              <span class="sort-arrow" aria-hidden="true">{sortDir === 'asc' ? '\u2191' : '\u2193'}</span>
            {/if}
          </th>
        {/each}
      </tr>
    </thead>
    <tbody>
      {#each rows as row, i (row.id ?? i)}
        <tr
          class:clickable={!!onRowClick}
          onclick={(e) => handleRowClick(row, e)}
          onkeydown={(e) => handleKeydown(row, e)}
          tabindex={onRowClick ? 0 : undefined}
          role={onRowClick ? 'button' : undefined}
        >
          {#each columns as col (col.key)}
            <td class:mono={col.mono} class:num={col.align === 'right'}>
              {#if col.render}
                {@html col.render(row[col.key], row, i)}
              {:else}
                {row[col.key] ?? '\u2014'}
              {/if}
            </td>
          {/each}
        </tr>
      {:else}
        <tr>
          <td colspan={columns.length} class="empty-cell">
            <span class="muted">{emptyMessage}</span>
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>

<style>
  .table-wrap {
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
  }
  table {
    min-width: 100%;
  }
  th.sortable {
    cursor: pointer;
    user-select: none;
  }
  th.sortable:hover {
    color: var(--fg);
  }
  th.active {
    color: var(--accent);
  }
  .sort-arrow {
    margin-left: var(--sp-1);
    font-size: 0.7em;
  }
  tr.clickable {
    cursor: pointer;
  }
  tr.clickable:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: -2px;
  }
  .empty-cell {
    text-align: center;
    padding: var(--sp-8) var(--sp-4);
  }
  .mono {
    font-family: var(--mono);
  }
  .num {
    text-align: right;
  }
</style>
