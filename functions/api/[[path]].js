const P_HASH = "aWtpbWk1MjA=";
const DB_FILE = ".ikimi_db.json";

async function getDB(env) {
  try {
    const obj = await env.BUCKET.get(DB_FILE);
    if (!obj) return { items: [] };
    return await obj.json();
  } catch (e) {
    return { items: [] };
  }
}

async function saveDB(env, db) {
  await env.BUCKET.put(DB_FILE, JSON.stringify(db));
}

function verifyToken(req) {
  const token = req.headers.get("X-Auth-Token") || new URL(req.url).searchParams.get("token");
  return token === P_HASH;
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api\/?/, "");

  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, HEAD",
    "Access-Control-Allow-Headers": "Content-Type, X-Auth-Token, Range",
    "Access-Control-Expose-Headers": "Content-Length, Content-Range, Content-Disposition",
  };

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (!env.BUCKET) {
    return new Response(JSON.stringify({ error: "BUCKET_UNBOUND" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  if (path === "auth/verify" && request.method === "POST") {
    const { password } = await request.json();
    if (btoa(password) === P_HASH) {
      return new Response(JSON.stringify({ token: P_HASH }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    return new Response(JSON.stringify({ error: "AUTH_FAILED" }), {
      status: 403,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  if (path === "auth/protect" && request.method === "POST") {
    if (!verifyToken(request)) {
      return new Response(null, { status: 403, headers: corsHeaders });
    }
    const { ids, protect } = await request.json();
    const db = await getDB(env);
    db.items = db.items.map((i) => (ids.includes(i.id) ? { ...i, isProtected: protect } : i));
    await saveDB(env, db);
    return new Response(JSON.stringify({ success: true }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  if (path === "files" && request.method === "GET") {
    const parentId = url.searchParams.get("parentId") || "root";
    const db = await getDB(env);

    const currentFolder = db.items.find((i) => i.id === parentId);
    if (currentFolder && currentFolder.isProtected && !verifyToken(request)) {
      return new Response(null, { status: 403, headers: corsHeaders });
    }

    const list = db.items.filter((i) => i.parentId === parentId);
    return new Response(JSON.stringify(list), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  if (path === "all-items" && request.method === "GET") {
    const db = await getDB(env);
    return new Response(JSON.stringify(db.items), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  if (path === "folder/create" && request.method === "POST") {
    const { name, parentId } = await request.json();
    const db = await getDB(env);

    const folder = {
      id: crypto.randomUUID(),
      name,
      parentId: parentId || "root",
      isFolder: true,
      size: 0,
      createdAt: Date.now(),
      isProtected: false,
    };

    db.items.push(folder);
    await saveDB(env, db);
    return new Response(JSON.stringify({ folder }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
  if (path === "upload" && request.method === "POST") {
    const formData = await request.formData();
    const file = formData.get("file");
    const parentId = formData.get("parentId") || "root";
    const fileId = crypto.randomUUID();

    const db = await getDB(env);
    const parent = db.items.find((i) => i.id === parentId);
    if (parent && parent.isProtected && !verifyToken(request)) {
      return new Response(null, { status: 403, headers: corsHeaders });
    }

    await env.BUCKET.put(fileId, file.stream(), {
      httpMetadata: { contentType: file.type || "application/octet-stream" },
    });

    const fileMeta = {
      id: fileId,
      name: file.name,
      parentId: parentId,
      isFolder: false,
      size: file.size,
      type: file.type || "application/octet-stream",
      uploadedAt: Date.now(),
      isProtected: false,
    };

    db.items.push(fileMeta);
    await saveDB(env, db);

    return new Response(JSON.stringify({ file: fileMeta }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  if (path === "view") {
    const id = url.searchParams.get("id");
    const db = await getDB(env);
    const item = db.items.find((i) => i.id === id);

    if (!item) return new Response("Not Found", { status: 404, headers: corsHeaders });
    if (item.isProtected && !verifyToken(request)) {
      return new Response(null, { status: 403, headers: corsHeaders });
    }

    if (request.method === "HEAD") {
      return new Response(null, { status: 200, headers: corsHeaders });
    }

    const obj = await env.BUCKET.get(id, {
      range: request.headers.get("Range"),
    });

    if (!obj) return new Response("Not Found", { status: 404, headers: corsHeaders });

    const headers = new Headers(corsHeaders);
    obj.writeHttpMetadata(headers);
    headers.set("etag", obj.httpEtag);
    headers.set("Content-Disposition", "inline");

    const currentType = headers.get("Content-Type");
    if (!currentType || currentType === "application/octet-stream") {
      const ext = (item.name || "").split(".").pop().toLowerCase();
      const mimeMap = {
        jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png", gif: "image/gif",
        webp: "image/webp", bmp: "image/bmp", svg: "image/svg+xml",
        mp4: "video/mp4", webm: "video/webm", ogg: "video/ogg",
        mp3: "audio/mpeg", wav: "audio/wav", flac: "audio/flac", aac: "audio/aac",
        pdf: "application/pdf", txt: "text/plain; charset=utf-8",
        json: "application/json", js: "application/javascript"
      };
      if (mimeMap[ext]) headers.set("Content-Type", mimeMap[ext]);
    }

    if (obj.range) {
      headers.set("Content-Range", `bytes ${obj.range.offset}-${obj.range.end}/${obj.size}`);
    }

    return new Response(obj.body, {
      status: obj.range ? 206 : 200,
      headers,
    });
  }

  if (path === "download") {
    const id = url.searchParams.get("id");
    const db = await getDB(env);
    const item = db.items.find((i) => i.id === id);

    if (!item) return new Response("Not Found", { status: 404, headers: corsHeaders });
    if (item.isProtected && !verifyToken(request)) {
      return new Response(JSON.stringify({ error: "LOCKED_FILE" }), {
        status: 403,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    if (request.method === "HEAD") {
      return new Response(null, { status: 200, headers: corsHeaders });
    }

    const obj = await env.BUCKET.get(id);
    if (!obj) return new Response("Not Found", { status: 404, headers: corsHeaders });

    const headers = new Headers(corsHeaders);
    headers.set("Content-Disposition", `attachment; filename*=UTF-8''${encodeURIComponent(item.name)}`);
    headers.set("Content-Type", item.type || "application/octet-stream");

    return new Response(obj.body, { headers });
  }

  if (path === "text/create" && request.method === "POST") {
    const { name, parentId, content } = await request.json();
    const fileId = crypto.randomUUID();
    const encoder = new TextEncoder();
    const bytes = encoder.encode(content);

    await env.BUCKET.put(fileId, bytes, {
      httpMetadata: { contentType: "text/plain; charset=utf-8" },
    });

    const db = await getDB(env);
    const fileMeta = {
      id: fileId,
      name,
      parentId: parentId || "root",
      isFolder: false,
      size: bytes.length,
      type: "text/plain; charset=utf-8",
      uploadedAt: Date.now(),
      isProtected: false,
    };
    db.items.push(fileMeta);
    await saveDB(env, db);

    return new Response(JSON.stringify({ file: fileMeta }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
  if (path === "text/save" && request.method === "POST") {
    const { id, name, content } = await request.json();
    const db = await getDB(env);
    const item = db.items.find((i) => i.id === id);

    if (!item) return new Response("Not Found", { status: 404, headers: corsHeaders });
    if (item.isProtected && !verifyToken(request)) {
      return new Response(null, { status: 403, headers: corsHeaders });
    }

    const encoder = new TextEncoder();
    const bytes = encoder.encode(content);
    await env.BUCKET.put(id, bytes, {
      httpMetadata: { contentType: "text/plain; charset=utf-8" },
    });

    item.name = name;
    item.size = bytes.length;
    item.uploadedAt = Date.now();
    await saveDB(env, db);

    return new Response(JSON.stringify({ file: item }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  if (path === "rename" && request.method === "POST") {
    const { id, newName } = await request.json();
    const db = await getDB(env);
    const item = db.items.find((i) => i.id === id);
    if (!item) return new Response("Not Found", { status: 404, headers: corsHeaders });
    if (item.isProtected && !verifyToken(request)) {
      return new Response(null, { status: 403, headers: corsHeaders });
    }
    item.name = newName;
    await saveDB(env, db);
    return new Response(JSON.stringify({ success: true }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  if (path === "move" && request.method === "POST") {
    const { id, targetParentId } = await request.json();
    const db = await getDB(env);
    const item = db.items.find((i) => i.id === id);
    if (!item) return new Response("Not Found", { status: 404, headers: corsHeaders });
    if (item.isProtected && !verifyToken(request)) {
      return new Response(null, { status: 403, headers: corsHeaders });
    }
    item.parentId = targetParentId;
    await saveDB(env, db);
    return new Response(JSON.stringify({ success: true }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  if (path === "copy" && request.method === "POST") {
    const { id, targetParentId } = await request.json();
    const db = await getDB(env);
    const item = db.items.find((i) => i.id === id);
    if (!item) return new Response("Not Found", { status: 404, headers: corsHeaders });

    if (!item.isFolder) {
      const newId = crypto.randomUUID();
      const originObj = await env.BUCKET.get(item.id);
      if (originObj) {
        await env.BUCKET.put(newId, originObj.body);
      }
      db.items.push({
        ...item,
        id: newId,
        parentId: targetParentId,
        uploadedAt: Date.now(),
      });
      await saveDB(env, db);
    }
    return new Response(JSON.stringify({ success: true }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  if (path === "delete" && request.method === "POST") {
    if (!verifyToken(request)) {
      return new Response(JSON.stringify({ error: "AUTH_REQUIRED" }), {
        status: 403,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const body = await request.json();
    const ids = body.ids || (body.id ? [body.id] : []);
    const db = await getDB(env);

    const toDeleteIds = new Set(ids);
    let queue = [...ids];
    while (queue.length > 0) {
      const curId = queue.shift();
      const children = db.items.filter((i) => i.parentId === curId);
      children.forEach((c) => {
        toDeleteIds.add(c.id);
        if (c.isFolder) queue.push(c.id);
      });
    }

    for (const deleteId of toDeleteIds) {
      const item = db.items.find((i) => i.id === deleteId);
      if (item && !item.isFolder) {
        await env.BUCKET.delete(deleteId);
      }
    }

    db.items = db.items.filter((i) => !toDeleteIds.has(i.id));
    await saveDB(env, db);

    return new Response(JSON.stringify({ success: true }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  if (path === "sync" && request.method === "GET") {
    if (!verifyToken(request)) {
      return new Response("Forbidden", { status: 403, headers: corsHeaders });
    }
    const db = await getDB(env);
    const existingIds = new Set(db.items.map((i) => i.id));
    let truncated = true;
    let cursor = undefined;
    let addedCount = 0;

    while (truncated) {
      const list = await env.BUCKET.list({ cursor });
      for (const obj of list.objects) {
        if (obj.key === DB_FILE || existingIds.has(obj.key)) continue;

        let cleanName = obj.key;
        if (cleanName.includes("/")) {
          cleanName = cleanName.split("/").pop();
        }

        db.items.push({
          id: obj.key,
          name: cleanName || obj.key,
          parentId: "root",
          isFolder: false,
          size: obj.size,
          type: obj.httpMetadata?.contentType || "application/octet-stream",
          uploadedAt: obj.uploaded ? new Date(obj.uploaded).getTime() : Date.now(),
          isProtected: false,
        });
        existingIds.add(obj.key);
        addedCount++;
      }
      truncated = list.truncated;
      cursor = list.cursor;
    }

    await saveDB(env, db);
    return new Response(JSON.stringify({ success: true, addedCount }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  return new Response("Not Found", { status: 404, headers: corsHeaders });
}

