import os
import datetime
import bcrypt
import math
import re
from flask import Flask, request, jsonify, redirect, url_for, session, render_template, flash, make_response
from functools import wraps, update_wrapper
from supabase import create_client, Client
from dotenv import load_dotenv
from collections import Counter

# --- CONFIGURAÇÃO INICIAL ---
load_dotenv()

url: str = os.getenv("SUPABASE_URL")
key: str = os.getenv("SUPABASE_KEY")

if not url or not key:
    raise ValueError("Erro: As variáveis SUPABASE_URL e SUPABASE_KEY não foram encontradas. Verifique seu arquivo .env.")
supabase: Client = create_client(url, key)
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "uma-chave-secreta-padrao-muito-segura")


# --- DECORATORS E FUNÇÕES HELPER ---
def nocache(view):
    @wraps(view)
    def no_cache(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Last-Modified'] = datetime.datetime.now()
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response
    return update_wrapper(no_cache, view)

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

def haversine(lat1, lon1, lat2, lon2):
    R = 6371.0
    lat1_rad = math.radians(lat1)
    lon1_rad = math.radians(lon1)
    lat2_rad = math.radians(lat2)
    lon2_rad = math.radians(lon2)
    dlon = lon2_rad - lon1_rad
    dlat = lat2_rad - lat1_rad
    a = math.sin(dlat / 2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    distance = R * c
    return distance

# --- ROTAS PÚBLICAS (LOGIN, CADASTRO, LOGOUT) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        cpf_input = request.form.get('cpf')
        senha_input = request.form.get('senha')

        if not cpf_input or not senha_input:
            flash('CPF e senha são obrigatórios.', 'erro')
            return render_template('login.html')

        cpf_limpo = re.sub(r'\D', '', cpf_input)

        try:
            result = supabase.table("tb_usuario").select("id_usuario, nome, senha, is_admin").eq("cpf", cpf_limpo).limit(1).execute()
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
            flash(f'Ocorreu um erro ao tentar fazer login: {e}', 'erro')
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
            
        cpf_limpo = re.sub(r'\D', '', cpf)

        try:
            existing_user = supabase.table("tb_usuario").select("cpf").eq("cpf", cpf_limpo).limit(1).execute()
            if existing_user.data:
                flash(f'O CPF {cpf} já está cadastrado.', 'erro')
                return render_template('cadastro.html')
            
            senha_hash = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            supabase.table("tb_usuario").insert({
                "nome": nome, "cpf": cpf_limpo, "email": email, "senha": senha_hash, "is_admin": False
            }).execute()
            flash(f'Seja bem-vindo(a), {nome}! Cadastro realizado com sucesso.', 'sucesso')
            return redirect(url_for('login'))
        except Exception as e:
            print(f"ERRO NO CADASTRO: {e}")
            flash(f'Ocorreu um erro ao cadastrar: {e}', 'erro')
    return render_template('cadastro.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Você saiu da sua conta.', 'sucesso')
    return redirect(url_for('login'))
@app.route('/')
def home():
    if session.get('logged_in'):
        return redirect(url_for('admin_dashboard')) if session.get('is_admin') else redirect(url_for('inicio'))
    return redirect(url_for('login'))

# --- ROTAS PRINCIPAIS (HOME, INICIO, PERFIL) ---
@app.route('/inicio')
@login_required()
def inicio():
    user_id = session.get('id_usuario')
    if not user_id:
        session.clear()
        return redirect(url_for('login'))

    acao = request.args.get('acao')
    if acao == 'perfil':
        return redirect(url_for('perfil'))
    if acao == 'eventos':
        return redirect(url_for('pagina_eventos'))
    
    eventos_de_hoje = []
    try:
        inscricoes_data = supabase.table("tb_usuario_evento").select("id_evento").eq("id_usuario", user_id).execute().data
        if inscricoes_data:
            ids_eventos_inscritos = [item['id_evento'] for item in inscricoes_data]
            eventos_inscritos = supabase.table("tb_evento").select("*").in_("id_evento", ids_eventos_inscritos).execute().data
            
            hoje = datetime.date.today()
            for evento in eventos_inscritos:
                data_evento_obj = datetime.datetime.fromisoformat(evento['data_evento']).date()
                if data_evento_obj == hoje:
                    presenca = supabase.table("tb_presenca").select("id_usuario").eq("id_evento", evento['id_evento']).eq("id_usuario", user_id).execute().data
                    if not presenca:
                        eventos_de_hoje.append(evento)

    except Exception as e:
        print(f"ERROR - Rota Inicio (eventos de hoje): {e}")
        flash('Erro ao carregar eventos do dia.', 'erro')

    return render_template('inicio.html', eventos_de_hoje=eventos_de_hoje)

@app.route('/perfil', methods=['GET', 'POST'])
@login_required()
def perfil():
    user_id = session.get('id_usuario')
    try:
        current_user_data = supabase.table("tb_usuario").select("nome, cpf, email").eq("id_usuario", user_id).single().execute().data
        if not current_user_data:
             raise Exception("Usuário não encontrado.")
    except Exception as e:
        flash(f'Não foi possível carregar os dados do perfil: {e}', 'erro')
        return redirect(url_for('inicio'))

    if request.method == 'POST':
        dados_para_atualizar = {}
        houve_alteracao = False
        
        novo_nome = request.form.get('nome')
        if novo_nome and novo_nome != current_user_data.get('nome'):
            dados_para_atualizar['nome'] = novo_nome
            houve_alteracao = True
        
        novo_cpf_mascarado = request.form.get('cpf')
        if novo_cpf_mascarado:
            novo_cpf_limpo = re.sub(r'\D', '', novo_cpf_mascarado)
            if novo_cpf_limpo != current_user_data.get('cpf'):
                outro_usuario = supabase.table("tb_usuario").select("id_usuario").eq("cpf", novo_cpf_limpo).neq("id_usuario", user_id).execute().data
                if outro_usuario:
                    flash(f'O CPF {novo_cpf_mascarado} já está em uso por outro usuário.', 'erro')
                    return render_template('perfil.html', usuario=current_user_data)
                
                dados_para_atualizar['cpf'] = novo_cpf_limpo
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
                flash(f'Ocorreu um erro ao salvar as alterações: {e}', 'erro')
        else:
            flash('Nenhuma alteração foi feita.', 'info')
        return redirect(url_for('perfil'))
        
    return render_template('perfil.html', usuario=current_user_data)

@app.route('/eventos')
@login_required()
def pagina_eventos():
    eventos_lista, eventos_inscritos_ids = [], []
    user_id = session.get('id_usuario')
    inscritos_count = {}
    try:
        inscricoes_req = supabase.table("tb_usuario_evento").select("id_evento").eq("id_usuario", user_id).execute()
        if inscricoes_req.data:
            eventos_inscritos_ids = [item['id_evento'] for item in inscricoes_req.data]
        eventos_req = supabase.table("tb_evento").select("*").order("data_evento", desc=True).execute()
        eventos_lista = eventos_req.data or []
        if eventos_lista:
            todas_inscricoes_req = supabase.table("tb_usuario_evento").select("id_evento").execute()
            if todas_inscricoes_req.data:
                lista_ids = [item['id_evento'] for item in todas_inscricoes_req.data]
                inscritos_count = Counter(lista_ids)
    except Exception as e:
        print(f"ERRO AO BUSCAR EVENTOS: {e}")
        flash("Ocorreu um erro ao carregar os eventos.", "erro")
    return render_template('eventos.html', 
                           eventos=eventos_lista, 
                           eventos_inscritos=eventos_inscritos_ids, 
                           inscritos_count=inscritos_count)

@app.route('/eventos/inscrever', methods=['POST'])
@login_required()
def inscrever_evento():
    user_id = session.get('id_usuario')
    id_evento = request.get_json().get('id_evento')
    try:
        evento_info = supabase.table("tb_evento").select("lotacao").eq("id_evento", id_evento).single().execute().data
        contagem_inscritos = supabase.table("tb_usuario_evento").select("id_evento", count='exact').eq("id_evento", id_evento).execute()
        lotacao_maxima = evento_info.get('lotacao')
        inscritos_atuais = contagem_inscritos.count
        if lotacao_maxima is not None and inscritos_atuais >= lotacao_maxima:
             return jsonify({"status": "erro", "message": "Este evento já atingiu a lotação máxima."}), 409
        supabase.table("tb_usuario_evento").insert({"id_usuario": user_id, "id_evento": id_evento}).execute()
        return jsonify({"status": "sucesso", "message": "Inscrição realizada com sucesso!"})
    except Exception as e:
        print(f"ERRO AO INSCREVER: {e}")
        return jsonify({"status": "erro", "message": "Você já está inscrito neste evento ou ocorreu um erro."}), 409

@app.route('/eventos/confirmar-presenca', methods=['POST'])
@login_required()
def confirmar_presenca():
    data = request.get_json()
    user_id = session.get('id_usuario')
    event_id = data.get('event_id')
    user_lat = float(data.get('lat'))
    user_lon = float(data.get('lon'))
    try:
        evento = supabase.table("tb_evento").select("latitude, longitude").eq("id_evento", event_id).single().execute().data
        if not evento or not evento.get('latitude') or not evento.get('longitude'):
            return jsonify({"status": "erro", "message": "Localização do evento não cadastrada."}), 400
        event_lat = float(evento['latitude'])
        event_lon = float(evento['longitude'])
        RAIO_MAXIMO_KM = 1.0 
        distancia = haversine(user_lat, user_lon, event_lat, event_lon)
        if distancia <= RAIO_MAXIMO_KM:
            supabase.table("tb_presenca").insert({
                "id_evento": event_id,
                "id_usuario": user_id
            }).execute()
            return jsonify({"status": "sucesso", "message": "Presença confirmada com sucesso!"})
        else:
            return jsonify({"status": "erro", "message": f"Você não está no local do evento. Distância: {distancia:.2f} km."}), 403
    except Exception as e:
        if '23505' in str(e):
             return jsonify({"status": "erro", "message": "Você já confirmou presença neste evento."}), 409
        print(f"ERRO AO CONFIRMAR PRESENÇA: {e}")
        return jsonify({"status": "erro", "message": "Ocorreu um erro ao processar sua solicitação."}), 500


# --- ROTAS DE ADMINISTRAÇÃO ---
@app.route('/admin')
@admin_required()
def admin_dashboard():
    return render_template('admin.html')


# --- GERENCIAMENTO DE USUÁRIOS (ADMIN) ---
@app.route('/admin/gerenciar-usuarios')
@admin_required()
@nocache
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
            
        cpf_limpo = re.sub(r'\D', '', cpf)

        try:
            existing_user = supabase.table("tb_usuario").select("cpf").eq("cpf", cpf_limpo).limit(1).execute()
            if existing_user.data:
                flash(f'O CPF {cpf} já está em uso.', 'erro')
                return render_template('adicionar_usuario.html')

            senha_hash = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            supabase.table("tb_usuario").insert({
                "nome": nome, "cpf": cpf_limpo, "email": email, "senha": senha_hash, "is_admin": is_admin
            }).execute()
            flash("Usuário adicionado com sucesso!", "sucesso")
        except Exception as e:
            flash(f"Ocorreu um erro ao adicionar o usuário: {e}", "erro")
        return redirect(url_for('gerenciar_usuarios'))
    return render_template('adicionar_usuario.html')

@app.route('/admin/usuarios/editar/<int:user_id>', methods=['GET', 'POST'])
@admin_required()
def editar_usuario_admin(user_id):
    try:
        usuario = supabase.table("tb_usuario").select("*").eq("id_usuario", user_id).single().execute().data
        if not usuario:
            raise Exception("Usuário não encontrado.")
    except Exception as e:
        flash(f"Não foi possível carregar usuário para edição: {e}", "erro")
        return redirect(url_for('gerenciar_usuarios'))

    if request.method == 'POST':
        novo_cpf_mascarado = request.form.get('cpf')
        novo_cpf_limpo = re.sub(r'\D', '', novo_cpf_mascarado)

        if novo_cpf_limpo and novo_cpf_limpo != usuario.get('cpf'):
            outro_usuario = supabase.table("tb_usuario").select("id_usuario").eq("cpf", novo_cpf_limpo).neq("id_usuario", user_id).execute().data
            if outro_usuario:
                flash(f'O CPF {novo_cpf_mascarado} já está em uso por outro usuário.', 'erro')
                return render_template('editar_usuario.html', usuario=usuario)
        
        dados_para_atualizar = {
            'nome': request.form.get('nome'),
            'cpf': novo_cpf_limpo,
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
            flash(f"Ocorreu um erro ao editar o usuário: {e}", "erro")
        return redirect(url_for('gerenciar_usuarios'))
        
    return render_template('editar_usuario.html', usuario=usuario)

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

@app.route('/admin/gerenciar-eventos')
@admin_required()
@nocache
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
            lotacao = request.form.get('lotacao')
            dados_evento = {
                "nome_evento": request.form.get('nome_evento'),
                "data_evento": request.form.get('data_evento'),
                "local": request.form.get('local'),
                "descricao": request.form.get('descricao'),
                "ativo": 'ativo' in request.form,
                "lotacao": int(lotacao) if lotacao and lotacao.isdigit() else None,
                "latitude": request.form.get('latitude') or None,
                "longitude": request.form.get('longitude') or None
            }
            supabase.table("tb_evento").insert(dados_evento).execute()
            flash("Evento adicionado com sucesso!", "sucesso")
        except ValueError:
             flash("O valor da lotação deve ser um número inteiro.", "erro")
        except Exception as e:
            print(f"ERRO ao adicionar evento: {e}")
            flash(f"Ocorreu um erro ao adicionar o evento: {e}", "erro")
        return redirect(url_for('gerenciar_eventos'))
    return render_template('adicionar_evento.html')

@app.route('/admin/eventos/editar/<int:event_id>', methods=['GET', 'POST'])
@admin_required()
def editar_evento_admin(event_id):
    if request.method == 'POST':
        try:
            lotacao = request.form.get('lotacao')
            dados_para_atualizar = {
                "nome_evento": request.form.get('nome_evento'),
                "data_evento": request.form.get('data_evento'),
                "local": request.form.get('local'),
                "descricao": request.form.get('descricao'),
                "ativo": 'ativo' in request.form,
                "lotacao": int(lotacao) if lotacao and lotacao.isdigit() else None,
                "latitude": request.form.get('latitude') or None,
                "longitude": request.form.get('longitude') or None
            }
            supabase.table("tb_evento").update(dados_para_atualizar).eq("id_evento", event_id).execute()
            flash("Evento atualizado com sucesso!", "sucesso")
        except ValueError:
             flash("O valor da lotação deve ser um número inteiro.", "erro")
        except Exception as e:
            print(f"ERRO ao editar evento: {e}")
            flash(f"Ocorreu um erro ao editar o evento: {e}", "erro")
        return redirect(url_for('gerenciar_eventos'))
    try:
        evento = supabase.table("tb_evento").select("*").eq("id_evento", event_id).single().execute().data
        if not evento:
            raise Exception("Evento não encontrado.")
        return render_template('editar_evento.html', evento=evento)
    except Exception as e:
        flash(f"Evento não encontrado ou erro ao carregar: {e}", "erro")
        return redirect(url_for('gerenciar_eventos'))

@app.route('/admin/eventos/atualizar-status', methods=['POST'])
@admin_required()
def atualizar_status_evento():
    data = request.get_json()
    try:
        novo_status = bool(data.get('ativo'))
        supabase.table("tb_evento").update({'ativo': novo_status}).eq("id_evento", data.get('event_id')).execute()
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
