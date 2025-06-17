
function exibirAlertaConfirmacao(titulo, texto, textoBotao, callbackConfirmar) {
    Swal.fire({
        title: titulo,
        text: texto,
        icon: 'question',
        showCancelButton: true,
        confirmButtonText: textoBotao,
        cancelButtonText: 'Cancelar'
    }).then((result) => {
        if (result.isConfirmed && typeof callbackConfirmar === 'function') {
            callbackConfirmar();
        }
    });
}

function exibirAlertaErro(titulo, texto) {
    return Swal.fire({
        title: titulo,
        text: texto,
        icon: 'error',
        confirmButtonText: 'OK'
    });
}

function exibirAlertaSucesso(titulo, texto) {
    return Swal.fire({
        title: titulo,
        text: texto,
        icon: 'success',
        confirmButtonText: 'OK'
    });
}
