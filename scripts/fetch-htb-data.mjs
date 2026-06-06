#!/usr/bin/env node
/**
 * Descarga tus máquinas pwneadas desde HTB API v4
 * Usa endpoints oficiales documentados en:
 * https://documenter.getpostman.com/view/13129365/TVeqbmeq
 */

import fs from 'node:fs/promises';

const HTB_TOKEN = process.env.HTB_TOKEN;
const HTB_USER_ID = '1534870';

if (!HTB_TOKEN) {
    console.error('❌ ERROR: Falta HTB_TOKEN');
    process.exit(1);
}

const HEADERS = {
    'Authorization': `Bearer ${HTB_TOKEN}`,
    'Accept': 'application/json',
    'User-Agent': 'Mozilla/5.0 warrior866-site',
};

const BASE_URL = 'https://www.hackthebox.com/api/v4';

async function htbFetch(url) {
    const res = await fetch(url, { headers: HEADERS });
    if (!res.ok) {
        throw new Error(`HTB ${res.status} en ${url}\n${await res.text()}`);
    }
    return res.json();
}

async function findWriteup(machineName, difficulty) {
    const slug = machineName.toLowerCase().replace(/\s+/g, '-');
    const diffMap = { 'Easy': 'easy', 'Medium': 'medium', 'Hard': 'hard', 'Insane': 'insane' };
    const diffFolder = diffMap[difficulty] || 'easy';
    try {
        await fs.access(`src/content/docs/es/htb/${diffFolder}/${slug}.md`);
        return `/es/htb/${diffFolder}/${slug}/`;
    } catch {
        return null;
    }
}

// Sleep para no disparar rate limits
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function main() {
    console.log('🔍 Descargando datos de HTB...\n');

    // 1. Perfil básico
    const profileData = await htbFetch(`${BASE_URL}/user/profile/basic/${HTB_USER_ID}`);
    const profile = profileData.profile;
    console.log(`✅ Usuario: ${profile.name} (Rank: ${profile.rank}, Nivel global: ${profile.ranking})`);

    // 2. Actividad (incluye todas las máquinas pwneadas)
    console.log('📥 Descargando actividad...');
    const activityData = await htbFetch(`${BASE_URL}/profile/activity/${HTB_USER_ID}`);
    const activity = activityData.profile?.activity || [];
    console.log(`   ${activity.length} eventos de actividad encontrados`);

    // 3. Filtrar solo machine owns y agrupar por máquina
    const machineMap = new Map();
    for (const event of activity) {
        if (event.object_type !== 'machine') continue;
        
        const id = event.id;
        if (!machineMap.has(id)) {
            machineMap.set(id, {
                id,
                name: event.name,
                avatar: event.machine_avatar,
                user_owned: false,
                root_owned: false,
                user_owned_date: null,
                root_owned_date: null,
                points_total: 0,
            });
        }
        
        const m = machineMap.get(id);
        if (event.type === 'user') {
            m.user_owned = true;
            // Quedarnos con la fecha más antigua (primer own)
            if (!m.user_owned_date || event.date < m.user_owned_date) {
                m.user_owned_date = event.date;
            }
        } else if (event.type === 'root') {
            m.root_owned = true;
            if (!m.root_owned_date || event.date < m.root_owned_date) {
                m.root_owned_date = event.date;
            }
        }
        m.points_total += event.points || 0;
    }

    console.log(`✅ ${machineMap.size} máquinas únicas pwneadas\n`);

    // 4. Para cada máquina, obtener OS y dificultad
    console.log('📥 Enriqueciendo cada máquina con OS y dificultad...');
    const machines = [];
    let counter = 0;
    
    for (const m of machineMap.values()) {
        counter++;
        try {
            const detailData = await htbFetch(`${BASE_URL}/machine/profile/${m.id}`);
            const info = detailData.info || {};
            
            const writeup = await findWriteup(m.name, info.difficultyText);
            
            machines.push({
                id: m.id,
                name: m.name,
                os: info.os || 'Unknown',
                difficulty: info.difficultyText || 'Unknown',
                points: info.points || 0,
                stars: info.stars || null,
                release: info.release || null,
                user_owned: m.user_owned,
                root_owned: m.root_owned,
                user_owned_date: m.user_owned_date,
                root_owned_date: m.root_owned_date,
                avatar: m.avatar,
                writeup,
            });
            
            process.stdout.write(`\r   ${counter}/${machineMap.size} - ${m.name.padEnd(30)}`);
            
            // Pequeña pausa para no saturar
            await sleep(150);
        } catch (err) {
            console.warn(`\n   ⚠️  Error con ${m.name}: ${err.message}`);
        }
    }
    console.log('\n');

    // 5. Ordenar por fecha (más reciente primero)
    machines.sort((a, b) => {
        const dA = new Date(a.root_owned_date || a.user_owned_date || 0);
        const dB = new Date(b.root_owned_date || b.user_owned_date || 0);
        return dB - dA;
    });

    // 6. Attack path chart (bonus)
    console.log('📥 Descargando attack paths...');
    let attackPaths = {};
    try {
        const chartData = await htbFetch(`${BASE_URL}/profile/chart/machines/attack/${HTB_USER_ID}`);
        attackPaths = chartData.profile?.machine_attack_paths || {};
        console.log(`✅ ${Object.keys(attackPaths).length} attack paths\n`);
    } catch (err) {
        console.warn(`⚠️  No se pudo obtener attack paths: ${err.message}\n`);
    }

    // 7. Output final
    const output = {
        updated_at: new Date().toISOString(),
        user: {
            id: profile.id,
            name: profile.name,
            rank: profile.rank,
            ranking: profile.ranking,
            points: profile.points,
            user_owns: profile.user_owns,
            system_owns: profile.system_owns,
            respects: profile.respects,
            country_name: profile.country_name,
            avatar: profile.avatar,
        },
        total: machines.length,
        attack_paths: attackPaths,
        machines,
    };

    await fs.mkdir('src/data', { recursive: true });
    await fs.writeFile('src/data/htb-machines.json', JSON.stringify(output, null, 2));

    // Stats finales
    const byDiff = { Easy: 0, Medium: 0, Hard: 0, Insane: 0 };
    const byOs = {};
    for (const m of machines) {
        byDiff[m.difficulty] = (byDiff[m.difficulty] || 0) + 1;
        byOs[m.os] = (byOs[m.os] || 0) + 1;
    }

    console.log('━'.repeat(50));
    console.log(`✅ JSON guardado en src/data/htb-machines.json`);
    console.log(`📊 Total máquinas: ${machines.length}`);
    console.log(`   Por dificultad: ${JSON.stringify(byDiff)}`);
    console.log(`   Por SO: ${JSON.stringify(byOs)}`);
    console.log(`🔗 Con writeup local: ${machines.filter(m => m.writeup).length}`);
    console.log('━'.repeat(50));
}

main().catch(err => {
    console.error('\n❌ Error:', err.message);
    process.exit(1);
});
