const apiUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const resultsPerPage = 10;
let currentPage = 1;
let totalRecords = 0;
async function fetchCVEData(page) {
    const startIndex = (page - 1) * resultsPerPage;
    const params = new URLSearchParams({
        resultsPerPage,
        startIndex
    });
    try {
        const response = await fetch(`${apiUrl}?${params.toString()}`);
        const data = await response.json();

        if (data.vulnerabilities) {
            totalRecords = data.totalResults;
            updateTable(data.vulnerabilities);
            updatePagination();
        }
    } catch (error) {
        console.error('Error fetching CVE data:', error);
    }
}
function updateTable(vulnerabilities) {
    const tbody = document.querySelector('#cveTable tbody');
    tbody.innerHTML = '';

    vulnerabilities.forEach(item => {
        const cve = item.cve;
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${cve.id || 'N/A'}</td>
            <td>${cve.descriptions?.[0]?.value || 'No description available'}</td>
            <td>${cve.published || 'N/A'}</td>
            <td>${cve.lastModified || 'N/A'}</td>
        `;
        tbody.appendChild(row);
    });
}
function updatePagination() {
    document.getElementById('pageInfo').textContent = `Page ${currentPage}`;
    document.getElementById('prevPage').disabled = currentPage === 1;
    document.getElementById('nextPage').disabled = currentPage * resultsPerPage >= totalRecords;
}
document.getElementById('prevPage').addEventListener('click', () => {
    if (currentPage > 1) {
        currentPage--;
        fetchCVEData(currentPage);
    }
});
document.getElementById('nextPage').addEventListener('click', () => {
    if (currentPage * resultsPerPage < totalRecords) {
        currentPage++;
        fetchCVEData(currentPage);
    }
});
fetchCVEData(currentPage);
