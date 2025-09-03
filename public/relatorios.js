document.addEventListener('DOMContentLoaded', () => {
    // 1. Código da foto
    const inputFoto = document.getElementById('input-foto');
    if (inputFoto) {
        inputFoto.addEventListener('change', function (event) {
            const preview = document.getElementById('preview-foto');
            const placeholder = document.querySelector('.placeholder');

            if (event.target.files && event.target.files[0]) {
                const reader = new FileReader();
                reader.onload = function (e) {
                    preview.src = e.target.result;
                    preview.style.display = 'block';
                    placeholder.style.display = 'none';
                };
                reader.readAsDataURL(event.target.files[0]);
            } else {
                preview.src = '#';
                preview.style.display = 'none';
                placeholder.style.display = 'block';
            }
        });
    }

    // 2. Código de busca
    const searchForm = document.getElementById('search-form');
    const searchInput = document.getElementById('morador');
    const searchBySelect = document.getElementById('tipoBuscas');
    const resultsContainer = document.getElementById('results');

    // Mapeamento dos valores do select para o nome das colunas do banco de dados
    const filterMap = {
        'name': 'name',
        'cpf': 'cpf',
        'rg': 'rg'
    };

    // Ação do formulário de busca
    if (searchForm) {
        searchForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const searchTerm = searchInput.value.trim();
            const searchBy = searchBySelect.value;
            const dbColumn = filterMap[searchBy];

            if (!searchTerm) {
                alert('Por favor, digite um valor para a busca.');
                return;
            }

            resultsContainer.innerHTML = '<div style="text-align: center; padding: 20px;">Buscando...</div>';

            const token = localStorage.getItem('token');
            if (!token) {
                resultsContainer.innerHTML = '<div style="text-align: center; padding: 20px; color: red;">Você não está autenticado. Faça login novamente.</div>';
                return;
            }

            try {
                const queryParams = new URLSearchParams({
                    [dbColumn]: searchTerm
                }).toString();

                const response = await fetch(`http://localhost:3001/api/moradores/busca?${queryParams}`, {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    }
                });

                if (!response.ok) {
                    const errorData = await response.json();
                    resultsContainer.innerHTML = `<div style="text-align: center; padding: 20px; color: red;">Erro: ${errorData.message}</div>`;
                    return;
                }

                const data = await response.json();

                resultsContainer.innerHTML = '';

                if (data.success && data.moradores.length > 0) {
                    data.moradores.forEach(user => {
                        const row = document.createElement('div');
                        row.className = 'linha-dados';

                        const dataFields = ['nomeCompleto', 'cpf', 'nome_mae', 'vulgo', 'informacao', 'antecedentes', 'imagen'];

                        dataFields.forEach(field => {
                            const cell = document.createElement('div');
                            cell.className = 'celula-dados';

                            if (field === 'imagen' && user[field]) {
                                const img = document.createElement('img');
                                img.src = `http://localhost:3001/uploads/${user[field]}`;
                                img.alt = 'Foto do morador';
                                img.style.width = '50px';
                                cell.appendChild(img);
                            } else {
                                cell.textContent = user[field] || 'N/A';
                            }

                            row.appendChild(cell);
                        });

                        resultsContainer.appendChild(row);
                    });
                } else {
                    resultsContainer.innerHTML = '<div style="text-align: center; padding: 20px;">Nenhum morador encontrado.</div>';
                }
            } catch (error) {
                console.error('Erro ao buscar morador:', error);
                resultsContainer.innerHTML = '<div style="text-align: center; padding: 20px; color: red;">Ocorreu um erro na busca.</div>';
            }
        });
    }
});