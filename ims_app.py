# ims_simple_app.py
# Streamlit IMS — Simple Mode (No Supabase Auth/Roles)
# Includes: Entry, Edit, Delete, File Upload, Attach, Export, Unsigned Rows

import os
import io
import json
from uuid import uuid4
from datetime import datetime, timezone
from typing import Dict, Any, List

import pandas as pd
import streamlit as st
from supabase import create_client, Client

# --------------------------
# Streamlit / Supabase setup
# --------------------------
st.set_page_config(page_title="IMS Simple", page_icon="🗂️", layout="wide")

SUPABASE_URL = st.secrets["supabase"]["url"]
SUPABASE_KEY = st.secrets["supabase"]["anon_key"]
BUCKET = st.secrets.get("supabase", {}).get("bucket", "ims-uploads")

sb: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

MAX_FILE_SIZE_MB = 50

# --------------------------
# Load form configs
# --------------------------
def load_json(path: str) -> Dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

forms_lw = load_json("form_configs.json")
forms_mpr = load_json("forms_mpr_configs.json")

if not forms_lw and not forms_mpr:
    st.error("⚠️ No config files found")
    st.stop()
# --------------------------
# File helpers
# --------------------------
def validate_uploaded_file(file) -> bool:
    if not file: return False
    size = len(file.getvalue())
    if size > MAX_FILE_SIZE_MB * 1024 * 1024:
        st.error(f"File too large: {size/1024/1024:.1f}MB (max {MAX_FILE_SIZE_MB}MB)")
        return False
    return True

def upload_files(form_code: str, files) -> tuple[List[str], List[Dict[str, Any]]]:
    paths, metadata = [], []
    folder = form_code.replace(" ", "_")
    for f in files or []:
        if not validate_uploaded_file(f): continue
        uid = str(uuid4())[:8]
        safe_name = f"{uid}_{f.name}"
        obj = f"{folder}/{safe_name}"
        data = f.getvalue()
        sb.storage.from_(BUCKET).upload(obj, data)
        paths.append(obj)
        metadata.append({
            "storage_path": obj,
            "original_name": f.name,
            "file_size": len(data),
            "uploaded_at": datetime.now(timezone.utc).isoformat(),
        })
        st.success(f"Uploaded: {f.name}")
    return paths, metadata

def get_file_download_url(path: str, name: str) -> str:
    try:
        return sb.storage.from_(BUCKET).get_public_url(path)
    except Exception:
        return f"{SUPABASE_URL}/storage/v1/object/public/{BUCKET}/{path}?download={name}"
# --------------------------
# Choose Form
# --------------------------
file_group = st.radio("Select file group", ["LW FILES", "M&PR FILES"], horizontal=True)
cfg = forms_lw if file_group == "LW FILES" else forms_mpr
form_code = st.selectbox("Choose form", list(cfg.keys()), format_func=lambda x: f"{x} — {cfg[x].get('title','')}")

conf = cfg[form_code]
fields = conf.get("fields", [])
sigs = conf.get("signatures", [])

# --------------------------
# Tabs
# --------------------------
tab_entry, tab_grid, tab_unsigned = st.tabs(
    ["📝 Form Entry", "📋 View & Edit", "⚠️ Unsigned Rows"]
)
with tab_entry:
    st.subheader(f"Form Entry — {conf.get('title', form_code)}")

    with st.form("entry_form"):
        values, sig_values = {}, {}
        cols = st.columns(2)
        for i, fld in enumerate(fields):
            with cols[i % 2]:
                is_long = any(k in fld.lower() for k in ["remarks","details","description","action","cause"])
                values[fld] = st.text_area(fld, height=100) if is_long else st.text_input(fld)

        if sigs:
            st.markdown("**Signatures**")
            sig_cols = st.columns(min(4, len(sigs)))
            for i, signer in enumerate(sigs):
                with sig_cols[i % len(sig_cols)]:
                    sig_values[signer] = st.checkbox(signer, value=False)

        uploads = st.file_uploader("Attach file(s)", type=None, accept_multiple_files=True)

        submitted = st.form_submit_button("💾 Save Entry", type="primary")

    if submitted:
        paths, metadata = upload_files(form_code, uploads) if uploads else ([], [])
        payload = {
            "file_type": file_group,
            "form_code": form_code,
            "data": values,
            "signatures": sig_values,
            "file_urls": paths,
            "file_metadata": metadata,
            "created_by": "IMS User",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        sb.table("ims_entries").insert(payload).execute()
        st.success("✅ Saved successfully!")
with tab_grid:
    st.caption("View, edit, delete, export, and attach files.")

    rows = (sb.table("ims_entries")
              .select("*")
              .eq("form_code", form_code)
              .order("created_at", desc=True)
              .limit(200)
              .execute().data or [])

    if not rows:
        st.info("No records yet.")
    else:
        # -------------------------
        # Normal Grid View (editable)
        # -------------------------
        flat = []
        for r in rows:
            d = r.get("data") or {}
            sig = r.get("signatures") or {}
            row = {"id": r.get("id"), "created_at": r.get("created_at")}
            for f in fields:
                row[f] = d.get(f, "")
            for s in sigs:
                row[f"✔ {s}"] = bool(sig.get(s, False))
            row["Files"] = ", ".join([m.get("original_name","") for m in r.get("file_metadata",[])])
            flat.append(row)

        df = pd.DataFrame(flat)
        st.markdown("### 📊 Grid View (Excel Style)")
        edited = st.data_editor(df, use_container_width=True, hide_index=True)

        if st.button("💾 Save edits", type="primary"):
            for _, er in edited.iterrows():
                rid = er["id"]
                new_data = {f: er.get(f, "") for f in fields}
                new_sigs = {s: bool(er.get(f"✔ {s}", False)) for s in sigs}
                sb.table("ims_entries").update({
                    "data": new_data,
                    "signatures": new_sigs
                }).eq("id", rid).execute()
            st.success("Changes saved.")
            st.rerun()

        # Export CSV
        csv = df.to_csv(index=False).encode("utf-8")
        st.download_button("⬇️ Download CSV", csv,
                           file_name=f"{form_code}.csv", mime="text/csv")

        # Delete rows
        del_ids = st.multiselect("Delete rows", options=[r["id"] for r in rows])
        if st.button("🗑️ Delete selected", type="secondary"):
            sb.table("ims_entries").delete().in_("id", del_ids).execute()
            st.success("Deleted selected rows.")
            st.rerun()

        # Attach files
        chosen_id = st.selectbox("Row to attach files", [r["id"] for r in rows])
        new_files = st.file_uploader("Attach new files", type=None, accept_multiple_files=True, key="attach")
        if st.button("Upload & attach"):
            paths, meta = upload_files(form_code, new_files)
            if paths:
                row = sb.table("ims_entries").select("file_urls,file_metadata").eq("id", chosen_id).single().execute().data
                existing_urls = row.get("file_urls") or []
                existing_meta = row.get("file_metadata") or []
                sb.table("ims_entries").update({
                    "file_urls": existing_urls + paths,
                    "file_metadata": existing_meta + meta
                }).eq("id", chosen_id).execute()
                st.success("Files attached.")
                st.rerun()

        # -------------------------
        # Canvas View (Readable Form Layout)
        # -------------------------
        st.markdown("### 🖼️ Canvas View (Readable Form Entries)")
        for r in rows:
            with st.expander(f"📄 {form_code} — Entry on {r.get('created_at','')[:10]} by {r.get('created_by','IMS User')}"):
                # Render fields in table
                df_view = pd.DataFrame((r.get("data") or {}).items(), columns=["Field", "Value"])
                st.table(df_view)

                # Show signatures
                sigs_done = [k for k,v in (r.get("signatures") or {}).items() if v]
                sigs_pending = [k for k,v in (r.get("signatures") or {}).items() if not v]
                st.markdown(f"**✅ Signed:** {', '.join(sigs_done) if sigs_done else 'None'}")
                st.markdown(f"**❌ Pending:** {', '.join(sigs_pending) if sigs_pending else 'None'}")

                # Show files
                if r.get("file_metadata"):
                    st.markdown("**📎 Attached Files:**")
                    for m in r["file_metadata"]:
                        url = get_file_download_url(m["storage_path"], m["original_name"])
                        st.markdown(f"- [{m['original_name']}]({url}) ({m['file_size']} bytes)")
with tab_unsigned:
    st.caption("Pending signatures grouped by form")

    rows = sb.table("ims_entries").select("*").limit(500).execute().data or []

    grouped = {}
    for r in rows:
        sigs = r.get("signatures") or {}
        missing = [s for s, v in sigs.items() if not v]
        if missing:
            form = r.get("form_code", "Unknown")
            grouped.setdefault(form, []).append({
                "id": r.get("id"),
                "created_by": r.get("created_by", "Unknown"),
                "created_at": r.get("created_at", "")[:10],
                "data": r.get("data", {}),
                "missing": missing
            })

    if not grouped:
        st.success("🎉 All entries fully signed!")
    else:
        for form_code, entries in grouped.items():
            st.subheader(f"📌 {form_code}")
            for e in entries:
                st.markdown(
                    f"""
                    <div style="border:1px solid #ccc; border-radius:10px; padding:15px; margin-bottom:15px; background:#f9f9f9;">
                        <h4>{form_code} — Entry on {e['created_at']} by {e['created_by']}</h4>
                        <p><b>❌ Missing:</b> {", ".join(e['missing'])}</p>
                        <hr>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

                # Show entry data in full width table
                df_view = pd.DataFrame(e["data"].items(), columns=["Field", "Value"])
                st.table(df_view)


# --------------------------
# Footer
# --------------------------
st.markdown("---")
st.caption("IMS • Simple Mode • Entry + Edit + Delete + Export + Unsigned Rows")
