
//Loads listensers after Document contenet has been loaded
document.addEventListener('DOMContentLoaded', function() {
    searchCVEs();
    
    document.getElementById('severityFilter').addEventListener('change', searchCVEs);
    document.getElementById('productFilter').addEventListener('change', searchCVEs);
    document.getElementById('stateFilter').addEventListener('change', searchCVEs);
});

//Search Function
async function searchCVEs() {
    
    //Obtains values
    //Or all/empty values if no input
    const searchQuery = document.getElementById('searchBox').value || '';
    const productFilter = document.getElementById('productFilter').value || 'all';
    const stateFilter = document.getElementById('stateFilter').value || 'all';
    const severityFilter = document.getElementById('severityFilter').value || 'all';

    //Collecting parameters to pass into query
    const params = new URLSearchParams({
        search: searchQuery,
        product: productFilter,
        state: stateFilter,
        severity: severityFilter
    });

    //Fetch
    try {
        const response = await fetch(`/search_cves?${params.toString()}`);
        const data = await response.json();

        //Updatable Table
        const tableBody = document.getElementById('cveTable');
        
        //Clear old content
        tableBody.innerHTML = '';

        //No results and table display
        if (data.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="7">No CVEs found.</td></tr>';
        } else {
            data.forEach(cve => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${cve.name}</td>
                    <td>${cve.description}</td>
                    <td>${cve.dateReviewed}</td>
                    <td>${cve.state}</td>
                    <td>${cve.severity || 'N/A'}</td>
                    <td>${cve.solution || 'N/A'}</td>
                    <td>${cve.productAffected}</td>
                `;
                tableBody.appendChild(row);
            });
        }

    //Debug catch for Py DB connector
    } catch (error) {
        console.error("Error fetching CVE data:", error);
    }
}