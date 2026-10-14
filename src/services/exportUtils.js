/**
 * Utility functions for exporting recon data in various formats.
 */

export function downloadFile(filename, content, type = 'text/plain') {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export function exportAllSubdomains(items) {
  const list = items.map(i => i.subdomain).join('\n');
  downloadFile('all_subdomains.txt', list);
}

export function exportLiveSubdomains(items) {
  const list = items
    .filter(i => i.status > 0)
    .map(i => i.subdomain)
    .join('\n');
  downloadFile('live_subdomains.txt', list);
}

export function exportLive200(items) {
  const list = items
    .filter(i => i.status === 200)
    .map(i => i.subdomain)
    .join('\n');
  downloadFile('live_200.txt', list);
}

export function exportLiveCsv(items) {
  const headers = ['Subdomain', 'Status', 'Category', 'Risk', 'IP', 'Final_URL'];
  const rows = items.map(i => [
    `"${i.subdomain}"`,
    i.status,
    `"${i.category || '-'}"`,
    `"${i.risk || 'INFO'}"`,
    `"${i.ip || '-'}"`,
    `"${i.finalUrl || '-'}"`
  ]);
  const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
  downloadFile('live_results.csv', csvContent, 'text/csv');
}

export function exportJson(items) {
  const jsonContent = JSON.stringify(items, null, 2);
  downloadFile('recon_results.json', jsonContent, 'application/json');
}
