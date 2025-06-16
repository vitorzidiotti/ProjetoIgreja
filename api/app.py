import os
import datetime
import bcrypt
from flask import Flask, request, jsonify, redirect, url_for, session, render_template, flash, send_from_directory
from functools import wraps
from supabase import create_client, Client
from dotenv import load_dotenv

# --- CONFIGURAÇÃO INICIAL ---
load_dotenv()

url: str = os.getenv("SUPABASE_URL")
key: str = os.getenv("SUPABASE_KEY")

if not url or not key:
    raise ValueError("Erro: As variáveis SUPABASE_URL e SUPABASE_KEY não foram encontradas. Verifique seu arquivo .env.")

supabase: Client = create_client(url, key)

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "uma-chave-secreta-padrao-muito-segura")

# --- DECORATORS (AUTENTICAÇÃO E AUTORIZAÇÃO) ---

# CORREÇÃO: Decorators ajustados para aceitar '()'
def login_required():
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'logged_in' not in session:
                flash('Por favor, faça login para acessar esta página.', 'erro')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

def admin_required():
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'logged_in' not in session:
                flash('Por favor, faça login para acessar esta página.', 'erro')
                return redirect(url_for('login'))
            if not session.get('is_admin'):
                flash('Você não tem permissão para acessar esta página.', 'erro')
                return redirect(url_for('inicio'))
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

# --- ROTAS PÚBLICAS (LOGIN, CADASTRO, LOGOUT) ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        cpf_input = request.form.get('cpf')
        senha_input = request.form.get('senha')
        if not cpf_input or not senha_input:
            flash('CPF e senha são obrigatórios.', 'erro')
            return render_template('login.html')
        try:
            result = supabase.table("tb_usuario").select("id_usuario, nome, senha, is_admin").eq("cpf", cpf_input).limit(1).execute()
            if result.data:
                usuario = result.data[0]
                stored_senha_hash = usuario['senha'].encode('utf-8')
                if bcrypt.checkpw(senha_input.encode('utf-8'), stored_senha_hash):
                    session['logged_in'] = True
                    session['id_usuario'] = usuario['id_usuario']
                    session['nome_usuario'] = usuario['nome']
                    session['is_admin'] = usuario.get('is_admin', False)
                    flash(f"Bem-vindo(a), {usuario['nome']}!", 'sucesso')
                    return redirect(url_for('admin_dashboard')) if session['is_admin'] else redirect(url_for('inicio'))
                else:
                    flash('CPF ou senha incorretos.', 'erro')
            else:
                flash('CPF ou senha incorretos.', 'erro')
        except Exception as e:
            print(f"ERRO NO LOGIN: {e}")
            flash('Ocorreu um erro ao tentar fazer login.', 'erro')
    return render_template('login.html')

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        nome = request.form.get('nome')
        cpf = request.form.get('cpf')
        email = request.form.get('email')
        senha = request.form.get('senha')
        if not all([nome, cpf, email, senha]):
            flash('Todos os campos são obrigatórios.', 'erro')
            return render_template('cadastro.html')
        try:
            existing_user = supabase.table("tb_usuario").select("cpf").eq("cpf", cpf).limit(1).execute()
            if existing_user.data:
                flash(f'O CPF {cpf} já está cadastrado.', 'erro')
                return render_template('cadastro.html')
            senha_hash = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            supabase.table("tb_usuario").insert({
                "nome": nome, "cpf": cpf, "email": email, "senha": senha_hash, "is_admin": False
            }).execute()
            flash(f'Seja bem-vindo(a), {nome}! Cadastro realizado com sucesso.', 'sucesso')
            return redirect(url_for('login'))
        except Exception as e:
            print(f"ERRO NO CADASTRO: {e}")
            flash('Ocorreu um erro ao cadastrar.', 'erro')
    return render_template('cadastro.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Você saiu da sua conta.', 'sucesso')
    return redirect(url_for('login'))

# --- ROTAS PRINCIPAIS (HOME, INICIO, PERFIL) ---

@app.route('/')
def home():
    if session.get('logged_in'):
        return redirect(url_for('admin_dashboard')) if session.get('is_admin') else redirect(url_for('inicio'))
    return redirect(url_for('login'))

@app.route('/inicio')
@login_required()
def inicio():
    acao = request.args.get('acao')
    user_id = session.get('id_usuario')

    if not user_id:
        session.clear()
        return redirect(url_for('login'))

    usuario_data = None
    
    try:
        # CORREÇÃO: Busca todos os dados necessários do usuário, incluindo o CPF.
        result_usuario = supabase.table("tb_usuario").select("nome, cpf").eq("id_usuario", user_id).limit(1).execute()
        
        if result_usuario.data:
            usuario_data = result_usuario.data[0]
        else:
            # Caso o ID na sessão seja inválido, limpa a sessão.
            flash('Sessão inválida. Por favor, faça login novamente.', 'erro')
            session.clear()
            return redirect(url_for('login'))

        # LÓGICA DE ROTEAMENTO: Decide qual página renderizar.  
        if acao == 'perfil':
            return redirect(url_for('perfil'))
        if acao == 'eventos':
            return redirect(url_for('pagina_eventos'))

        # Se não houver 'acao' ou for outra coisa, renderiza a página inicial padrão.
        eventos = []
        hoje = datetime.datetime.now().isoformat()
        result_eventos = supabase.table("tb_evento").select("*").gte("data_evento", hoje).order("data_evento", desc=False).execute()
        if result_eventos.data:
            eventos = result_eventos.data
            
        return render_template('inicio.html', usuario=usuario_data, eventos=eventos)

    except Exception as e:
        print(f"ERROR - Rota Inicio: Erro ao buscar dados: {e}")
        flash('Erro ao carregar a página.', 'erro')
        # Em caso de erro, redirecionar para o login é uma medida segura.
        return redirect(url_for('login'))


@app.route('/perfil', methods=['GET', 'POST'])
@login_required()
def perfil():
    user_id = session.get('id_usuario')
    try:
        current_user_result = supabase.table("tb_usuario").select("nome, cpf, email").eq("id_usuario", user_id).single().execute()
        current_user_data = current_user_result.data
    except Exception as e:
        flash('Não foi possível carregar os dados do perfil.', 'erro')
        return redirect(url_for('inicio'))

    if request.method == 'POST':
        dados_para_atualizar = {}
        houve_alteracao = False
        
        novo_nome = request.form.get('nome')
        if novo_nome and novo_nome != current_user_data.get('nome'):
            dados_para_atualizar['nome'] = novo_nome
            houve_alteracao = True

        novo_cpf = request.form.get('cpf')
        if novo_cpf and novo_cpf != current_user_data.get('cpf'):
            dados_para_atualizar['cpf'] = novo_cpf
            houve_alteracao = True
            
        novo_email = request.form.get('email')
        if novo_email and novo_email != current_user_data.get('email'):
            dados_para_atualizar['email'] = novo_email
            houve_alteracao = True

        nova_senha = request.form.get('nova_senha')
        if nova_senha:
            confirmar_senha = request.form.get('confirmar_senha')
            if nova_senha != confirmar_senha:
                flash('As senhas não coincidem. Tente novamente.', 'erro')
                return render_template('perfil.html', usuario=current_user_data)
            senha_hash = bcrypt.hashpw(nova_senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            dados_para_atualizar['senha'] = senha_hash
            houve_alteracao = True
        
        if houve_alteracao:
            try:
                supabase.table("tb_usuario").update(dados_para_atualizar).eq("id_usuario", user_id).execute()
                if 'nome' in dados_para_atualizar:
                    session['nome_usuario'] = dados_para_atualizar['nome']
                flash('Perfil atualizado com sucesso!', 'sucesso')
            except Exception as e:
                flash('Ocorreu um erro ao salvar as alterações.', 'erro')
        else:
            flash('Nenhuma alteração foi feita.', 'info')
        return redirect(url_for('perfil'))
        
    return render_template('perfil.html', usuario=current_user_data)

# --- ROTAS DE EVENTOS (VISUALIZAÇÃO DO USUÁRIO) ---

@app.route('/eventos')
@login_required()
def pagina_eventos():
    eventos_lista, eventos_inscritos_ids = [], []
    user_id = session.get('id_usuario')
    try:
        inscricoes_req = supabase.table("tb_usuario_evento").select("id_evento").eq("id_usuario", user_id).execute()
        if inscricoes_req.data:
            eventos_inscritos_ids = [item['id_evento'] for item in inscricoes_req.data]
        eventos_req = supabase.table("tb_evento").select("*").order("data_evento", desc=True).execute()
        if eventos_req.data:
            eventos_lista = eventos_req.data
    except Exception as e:
        print(f"ERRO AO BUSCAR EVENTOS: {e}")
        flash("Ocorreu um erro ao carregar os eventos.", "erro")
    return render_template('eventos.html', eventos=eventos_lista, eventos_inscritos=eventos_inscritos_ids)

@app.route('/eventos/inscrever', methods=['POST'])
@login_required()
def inscrever_evento():
    user_id = session.get('id_usuario')
    id_evento = request.get_json().get('id_evento')
    try:
        supabase.table("tb_usuario_evento").insert({"id_usuario": user_id, "id_evento": id_evento}).execute()
        return jsonify({"status": "sucesso", "message": "Inscrição realizada com sucesso!"})
    except Exception:
        return jsonify({"status": "erro", "message": "Você já está inscrito neste evento."}), 409

# --- ROTAS DE ADMINISTRAÇÃO ---

@app.route('/admin')
@admin_required()
def admin_dashboard():
    return render_template('admin.html')

# --- GERENCIAMENTO DE USUÁRIOS (ADMIN) ---

@app.route('/admin/gerenciar-usuarios')
@admin_required()
def gerenciar_usuarios():
    try:
        usuarios = supabase.table("tb_usuario").select("*").order("nome").execute()
        return render_template('gerenciar_usuarios.html', usuarios=usuarios.data)
    except Exception as e:
        flash("Não foi possível carregar a lista de usuários.", "erro")
        return render_template('gerenciar_usuarios.html', usuarios=[])

@app.route('/admin/usuarios/adicionar', methods=['GET', 'POST'])
@admin_required()
def adicionar_usuario():
    if request.method == 'POST':
        nome = request.form.get('nome')
        cpf = request.form.get('cpf')
        email = request.form.get('email')
        senha = request.form.get('senha')
        is_admin = 'is_admin' in request.form
        if not all([nome, cpf, email, senha]):
            flash("Todos os campos são obrigatórios.", "erro")
            return render_template('adicionar_usuario.html')
        try:
            senha_hash = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            supabase.table("tb_usuario").insert({
                "nome": nome, "cpf": cpf, "email": email, "senha": senha_hash, "is_admin": is_admin
            }).execute()
            flash("Usuário adicionado com sucesso!", "sucesso")
        except Exception as e:
            flash("Ocorreu um erro ao adicionar o usuário.", "erro")
        return redirect(url_for('gerenciar_usuarios'))
    return render_template('adicionar_usuario.html')

@app.route('/admin/usuarios/editar/<int:user_id>', methods=['GET', 'POST'])
@admin_required()
def editar_usuario_admin(user_id):
    if request.method == 'POST':
        dados_para_atualizar = {
            'nome': request.form.get('nome'),
            'cpf': request.form.get('cpf'),
            'email': request.form.get('email'),
            'is_admin': 'is_admin' in request.form
        }
        nova_senha = request.form.get('senha')
        if nova_senha:
            senha_hash = bcrypt.hashpw(nova_senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            dados_para_atualizar['senha'] = senha_hash
        try:
            supabase.table("tb_usuario").update(dados_para_atualizar).eq("id_usuario", user_id).execute()
            flash("Usuário atualizado com sucesso!", "sucesso")
        except Exception as e:
            flash("Ocorreu um erro ao editar o usuário.", "erro")
        return redirect(url_for('gerenciar_usuarios'))
    try:
        usuario = supabase.table("tb_usuario").select("*").eq("id_usuario", user_id).single().execute()
        return render_template('editar_usuario.html', usuario=usuario.data)
    except Exception as e:
        return redirect(url_for('gerenciar_usuarios'))

@app.route('/admin/usuarios/atualizar-status', methods=['POST'])
@admin_required()
def atualizar_status_usuario():
    data = request.get_json()
    try:
        supabase.table("tb_usuario").update({'is_admin': data.get('is_admin')}).eq("id_usuario", data.get('user_id')).execute()
        return jsonify({"status": "sucesso", "message": "Status do usuário atualizado."})
    except Exception as e:
        return jsonify({"status": "erro", "message": str(e)}), 500

@app.route('/admin/usuarios/excluir', methods=['POST'])
@admin_required()
def excluir_usuario():
    data = request.get_json()
    try:
        supabase.table("tb_usuario").delete().eq("id_usuario", data.get('user_id')).execute()
        return jsonify({"status": "sucesso", "message": "Usuário excluído."})
    except Exception as e:
        return jsonify({"status": "erro", "message": str(e)}), 500

# --- GERENCIAMENTO DE EVENTOS (ADMIN) ---

@app.route('/admin/gerenciar-eventos')
@admin_required()
def gerenciar_eventos():
    try:
        eventos = supabase.table("tb_evento").select("*").order("data_evento", desc=True).execute()
        return render_template('gerenciar_eventos.html', eventos=eventos.data)
    except Exception as e:
        print(f"ERRO ao buscar eventos: {e}")
        flash("Não foi possível carregar a lista de eventos.", "erro")
        return render_template('gerenciar_eventos.html', eventos=[])

@app.route('/admin/eventos/adicionar', methods=['GET', 'POST'])
@admin_required()
def adicionar_evento():
    if request.method == 'POST':
        try:
            supabase.table("tb_evento").insert({
                "nome_evento": request.form.get('nome_evento'),
                "data_evento": request.form.get('data_evento'),
                "local": request.form.get('local'),
                "descricao": request.form.get('descricao'),
                "ativo": 'ativo' in request.form
            }).execute()
            flash("Evento adicionado com sucesso!", "sucesso")
        except Exception as e:
            print(f"ERRO ao adicionar evento: {e}")
            flash("Ocorreu um erro ao adicionar o evento.", "erro")
        return redirect(url_for('gerenciar_eventos'))
    return render_template('adicionar_evento.html')

@app.route('/admin/eventos/editar/<int:event_id>', methods=['GET', 'POST'])
@admin_required()
def editar_evento_admin(event_id):
    if request.method == 'POST':
        try:
            dados_para_atualizar = {
                "nome_evento": request.form.get('nome_evento'),
                "data_evento": request.form.get('data_evento'),
                "local": request.form.get('local'),
                "descricao": request.form.get('descricao'),
                "ativo": 'ativo' in request.form
            }
            supabase.table("tb_evento").update(dados_para_atualizar).eq("id_evento", event_id).execute()
            flash("Evento atualizado com sucesso!", "sucesso")
        except Exception as e:
            print(f"ERRO ao editar evento: {e}")
            flash("Ocorreu um erro ao editar o evento.", "erro")
        return redirect(url_for('gerenciar_eventos'))
    try:
        evento = supabase.table("tb_evento").select("*").eq("id_evento", event_id).single().execute()
        if not evento.data:
            flash("Evento não encontrado.", "erro")
            return redirect(url_for('gerenciar_eventos'))
        return render_template('editar_evento.html', evento=evento.data)
    except Exception as e:
        return redirect(url_for('gerenciar_eventos'))

@app.route('/admin/eventos/atualizar-status', methods=['POST'])
@admin_required()
def atualizar_status_evento():
    data = request.get_json()
    try:
        supabase.table("tb_evento").update({'ativo': data.get('ativo')}).eq("id_evento", data.get('event_id')).execute()
        return jsonify({"status": "sucesso", "message": "Status do evento atualizado."})
    except Exception as e:
        return jsonify({"status": "erro", "message": str(e)}), 500

@app.route('/admin/eventos/excluir', methods=['POST'])
@admin_required()
def excluir_evento():
    data = request.get_json()
    try:
        supabase.table("tb_evento").delete().eq("id_evento", data.get('event_id')).execute()
        return jsonify({"status": "sucesso", "message": "Evento excluído."})
    except Exception as e:
        return jsonify({"status": "erro", "message": str(e)}), 500

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
