import streamlit as st
import pandas as pd
import json
import base64
import os
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import io

# --- Configuration ---
st.set_page_config(
    page_title="指導の記録",
    page_icon="📝",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- CSS Styling (Premium Look) ---
st.markdown("""
    <style>
    .stApp {
        background-color: #f8fafc;
    }
    .main-header {
        font-size: 2rem;
        color: #1e293b;
        font-weight: 700;
        margin-bottom: 1rem;
    }
    .card {
        background: white;
        padding: 1.5rem;
        border-radius: 12px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        margin-bottom: 1rem;
    }
    /* Hide Streamlit Menu for cleaner look */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    </style>
""", unsafe_allow_html=True)

# --- Helper Functions ---

def load_data():
    """Load data from session state or initialize."""
    if 'students' not in st.session_state:
        st.session_state.students = []
    if 'records' not in st.session_state:
        st.session_state.records = []

def generate_record_id():
    return datetime.now().strftime("%Y%m%d%H%M%S")

def encrypt_data(data_json, password):
    """Encrypt JSON string using AES-GCM derived from password."""
    # Salt generation
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    data_bytes = data_json.encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, data_bytes, None)
    
    # Store as JSON structure with base64 encoded parts
    encrypted_blob = {
        "salt": base64.b64encode(salt).decode('utf-8'),
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
    }
    return json.dumps(encrypted_blob)

def decrypt_data(encrypted_json, password):
    """Decrypt JSON string."""
    try:
        blob = json.loads(encrypted_json)
        salt = base64.b64decode(blob['salt'])
        nonce = base64.b64decode(blob['nonce'])
        ciphertext = base64.b64decode(blob['ciphertext'])
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password.encode())
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')
    except Exception as e:
        return None

# --- Main App Logic ---

def main():
    load_data()

    # --- Sidebar ---
    with st.sidebar:
        st.title("📝 指導の記録")
        
        mode = st.radio("メニュー", ["記録入力", "履歴一覧", "設定・データ管理"], index=0)
        
        st.markdown("---")
        st.caption("Auto-saved to Session State (Not Permanent)")

    # --- Mode: 記録入力 (Record Input) ---
    if mode == "記録入力":
        st.markdown('<div class="main-header">記録を入力</div>', unsafe_allow_html=True)
        
        # 1. Date and Student Selection
        col1, col2 = st.columns([1, 2])
        with col1:
             selected_date = st.date_input("日付", value=datetime.today())
        with col2:
             if not st.session_state.students:
                 st.warning("生徒が登録されていません。「設定・データ管理」から生徒を追加してください。")
                 selected_student = None
             else:
                 selected_student = st.selectbox("生徒を選択", st.session_state.students)

        if selected_student:
             with st.form("record_form"):
                st.subheader(f"{selected_student} さんの記録")
                
                c1, c2 = st.columns(2)
                with c1:
                    period = st.selectbox("時限", ["1限", "2限", "3限", "4限", "5限", "6限", "朝", "帰り", "その他"])
                with c2:
                    subject = st.selectbox("教科", 
                        ["国語", "社会", "数学", "理科", "音楽", "美術", "保健体育", "技術・家庭", "外国語", "自立活動", "その他"]
                    )
                    if subject == "その他":
                        subject_detail = st.text_input("教科名を入力")
                        if subject_detail: subject = subject_detail

                unit = st.text_input("単元", placeholder="例: かけ算九九")

                st.write("評価の観点")
                perspective = st.radio("観点を選択", ["K (知識・技能)", "T (思考・判断・表現)", "A (主体的に取り組む態度)"], horizontal=True)
                
                # Extract clean value (K, T, A)
                p_val = perspective.split(" ")[0]

                situation = st.selectbox("観察した場面", ["全体発問", "グループ活動", "個別作業", "発表", "その他"])
                if situation == "その他":
                    situation_custom = st.text_input("場面を入力")
                    if situation_custom: situation = situation_custom

                achievement = st.text_area("できたこと（事実＋短い解釈）", height=100, placeholder="例: ○○を使って、最後まで計算できた。")
                support = st.text_area("手立て（工夫・支援）", height=80, placeholder="例: 具体物を提示した、手順表を渡した")
                next_steps = st.text_input("次時の手立てメモ", placeholder="例: 補助なしでやってみる")

                submit = st.form_submit_button("保存する", type="primary")

                if submit:
                    if not achievement:
                        st.error("「できたこと」は必須入力です")
                    else:
                        new_record = {
                            "id": generate_record_id(),
                            "date": selected_date.strftime("%Y-%m-%d"),
                            "student": selected_student,
                            "period": period,
                            "subject": subject,
                            "unit": unit,
                            "perspective": p_val,
                            "situation": situation,
                            "achievement": achievement,
                            "support": support,
                            "next_steps": next_steps,
                            "timestamp": datetime.now().isoformat()
                        }
                        st.session_state.records.insert(0, new_record) # Add to top
                        st.success("保存しました！")
                        # We don't clear form automatically in Streamlit easily without rerun tricks, 
                        # but user can just overwrite for next entry.

    # --- Mode: 履歴一覧 (History) ---
    elif mode == "履歴一覧":
        st.markdown('<div class="main-header">記録一覧</div>', unsafe_allow_html=True)

        if not st.session_state.records:
            st.info("記録はまだありません。")
        else:
            # Filters
            f_col1, f_col2 = st.columns(2)
            with f_col1:
                filter_student = st.multiselect("生徒で絞り込み", st.session_state.students)
            with f_col2:
                # Simple text search could go here
                pass

            # Filter Logic
            display_records = st.session_state.records
            if filter_student:
                display_records = [r for r in display_records if r['student'] in filter_student]

            # Display as Table
            df = pd.DataFrame(display_records)
            
            # Reorder columns for display
            if not df.empty:
                cols_order = ["date", "period", "student", "subject", "unit", "perspective", "situation", "achievement", "support", "next_steps"]
                # Keep only existing columns incase empty keys
                cols_order = [c for c in cols_order if c in df.columns]
                st.dataframe(df[cols_order], use_container_width=True, hide_index=True)
            
            st.divider()
            
            # Excel Download
            if not df.empty:
                buffer = io.BytesIO()
                with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
                    df.to_excel(writer, index=False, sheet_name='記録')
                
                st.download_button(
                    label="Excel形式でダウンロード",
                    data=buffer.getvalue(),
                    file_name=f"achievement_records_{datetime.now().strftime('%Y%m%d')}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )

    # --- Mode: 設定・データ管理 (Settings) ---
    elif mode == "設定・データ管理":
        st.markdown('<div class="main-header">設定・データ管理</div>', unsafe_allow_html=True)
        
        with st.expander("生徒管理", expanded=True):
            st.write("登録済み生徒:")
            if st.session_state.students:
                for s in st.session_state.students:
                    st.text(f"- {s}")
            else:
                st.write("(なし)")
            
            new_student = st.text_input("新しい生徒名を追加")
            if st.button("追加"):
                if new_student and new_student not in st.session_state.students:
                    st.session_state.students.append(new_student)
                    st.success(f"{new_student} を追加しました")
                    st.rerun()

        st.divider()

        st.subheader("バックアップと復元")
        st.warning("⚠️ Streamlit Cloud等のサーバー上では、ページをリロードするとデータが消える場合があります。作業終了時は必ずバックアップを保存してください。")

        # Backup
        col_b1, col_b2 = st.columns(2)
        with col_b1:
            st.markdown("#### バックアップ (保存)")
            backup_pass = st.text_input("パスワード設定 (任意)", type="password", key="backup_pass")
            
            full_data = {
                "students": st.session_state.students,
                "records": st.session_state.records
            }
            json_str = json.dumps(full_data, ensure_ascii=False, indent=2)
            
            if backup_pass:
                # Encrypt
                final_data = encrypt_data(json_str, backup_pass)
                file_name = f"backup_encrypted_{datetime.now().strftime('%Y%m%d')}.json"
                mime = "application/json"
            else:
                final_data = json_str
                file_name = f"backup_plain_{datetime.now().strftime('%Y%m%d')}.json"
                mime = "application/json"
                
            st.download_button(
                label="バックアップファイルをダウンロード",
                data=final_data,
                file_name=file_name,
                mime=mime,
                type="primary"
            )

        # Restore
        with col_b2:
            st.markdown("#### 復元 (読み込み)")
            uploaded_file = st.file_uploader("バックアップファイル (.json) を選択", type=['json'])
            restore_pass = st.text_input("パスワード (設定した場合)", type="password", key="restore_pass")
            
            if uploaded_file is not None:
                if st.button("復元を実行"):
                    try:
                        content = uploaded_file.getvalue().decode('utf-8')
                        
                        # Try parsing as plain JSON first to check format
                        try:
                            data = json.loads(content)
                            # Check if it looks like our encrypted blob
                            if 'ciphertext' in data and 'salt' in data and 'nonce' in data:
                                is_encrypted = True
                            else:
                                is_encrypted = False
                        except:
                            st.error("ファイル読み込みエラー")
                            st.stop()
                        
                        final_json = None
                        if is_encrypted:
                            if not restore_pass:
                                st.error("パスワードが必要です")
                            else:
                                decrypted = decrypt_data(content, restore_pass)
                                if decrypted:
                                    final_json = json.loads(decrypted)
                                else:
                                    st.error("パスワードが間違っているか、ファイルが破損しています")
                        else:
                            final_json = data
                        
                        if final_json:
                            st.session_state.students = final_json.get('students', [])
                            st.session_state.records = final_json.get('records', [])
                            st.success("復元しました！")
                            st.rerun()
                            
                    except Exception as e:
                        st.error(f"エラーが発生しました: {e}")

if __name__ == "__main__":
    main()
