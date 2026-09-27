-- USLocalServer 本地存档基线 schema（SQLite）。
CREATE TABLE IF NOT EXISTS character_previous_village (
    character_id INTEGER NOT NULL PRIMARY KEY REFERENCES characters(character_id) ON DELETE CASCADE,
    town_id INTEGER NOT NULL CHECK(town_id > 0),
    area_id INTEGER NOT NULL CHECK(area_id >= 0),
    position_x INTEGER NOT NULL CHECK(position_x BETWEEN -32768 AND 32767),
    position_y INTEGER NOT NULL CHECK(position_y BETWEEN -32768 AND 32767),
    town_state INTEGER NOT NULL CHECK(town_state BETWEEN 0 AND 255)
);
--
-- 迁移来源：Reference/110US/.../fake_server/db/bootstrap_repo.py 的 MySQL
-- schema v4。表名、列名和默认值保持一致，便于与 Python 原型的行为对照；
-- 类型和约束按 SQLite 重写：
--   * INT/BIGINT UNSIGNED           -> INTEGER + CHECK (>= 0)
--   * VARCHAR(n)                    -> TEXT + CHECK (length(...) <= n)
--   * TINYINT(1)                    -> INTEGER + CHECK (IN (0, 1))
--   * ENGINE/CHARSET/COLLATE 子句   -> 删除（SQLite 无此概念）
--   * 命名 UNIQUE KEY               -> 独立的 CREATE UNIQUE INDEX
-- 外键需要连接级 PRAGMA foreign_keys = ON，由 SqliteConnectionFactory 负责。
--
-- 禁止把 86JP A21 的表名、字段、ItemCore 布局或任务语义引入本文件。

CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER NOT NULL PRIMARY KEY,
    applied_at INTEGER NOT NULL,
    CHECK (version >= 0),
    CHECK (applied_at >= 0)
);

-- cera 是账号级的点券余额（商城货币），不是角色级的金币——金币住在主背包 0 号虚拟槽里。
--
-- 默认值不是 0：这是一台本地单机服务端，点券没有任何别的来源，余额为 0 时商城这一块
-- 根本看不出有没有通。改这个默认值只影响**新建**的账号，老账号补列时拿到的也是它。
CREATE TABLE IF NOT EXISTS accounts (
    account_id INTEGER NOT NULL PRIMARY KEY,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    cera       INTEGER NOT NULL DEFAULT 100000,
    CHECK (account_id >= 0),
    CHECK (created_at >= 0),
    CHECK (updated_at >= 0),
    CHECK (cera >= 0)
);

CREATE TABLE IF NOT EXISTS account_radiant_boxes (
    account_id INTEGER NOT NULL REFERENCES accounts(account_id),
    version INTEGER NOT NULL CHECK(version > 0),
    opened INTEGER NOT NULL CHECK(opened BETWEEN 0 AND 2147483647),
    PRIMARY KEY(account_id,version)
);

CREATE TABLE IF NOT EXISTS account_character_capacity (
    account_id INTEGER NOT NULL PRIMARY KEY REFERENCES accounts(account_id),
    capacity INTEGER NOT NULL CHECK(capacity BETWEEN 32 AND 77),
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS account_materials (
    account_id INTEGER NOT NULL,
    item_id    INTEGER NOT NULL,
    count      INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (account_id, item_id),
    CHECK (item_id BETWEEN 1 AND 2147483647),
    CHECK (typeof(count) = 'integer' AND count BETWEEN 0 AND 2147483647),
    CHECK (updated_at >= 0),
    FOREIGN KEY (account_id) REFERENCES accounts (account_id)
);

-- Premium contracts are account-owned. Expiry is absolute Unix seconds in storage;
-- role selection and activation notifications project it as remaining seconds.
CREATE TABLE IF NOT EXISTS account_premium_contracts (
    account_id   INTEGER NOT NULL,
    premium_type INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL,
    PRIMARY KEY (account_id, premium_type),
    CHECK (premium_type BETWEEN 1 AND 255),
    CHECK (expires_at >= 0),
    CHECK (updated_at >= 0),
    FOREIGN KEY (account_id) REFERENCES accounts (account_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS channel_servers (
    server_id    INTEGER NOT NULL PRIMARY KEY,
    wire_name    TEXT    NOT NULL,
    display_name TEXT    NOT NULL,
    sort_order   INTEGER NOT NULL,
    is_enabled   INTEGER NOT NULL DEFAULT 1,
    CHECK (server_id >= 0),
    CHECK (length(wire_name) BETWEEN 1 AND 20),
    CHECK (length(display_name) BETWEEN 1 AND 40),
    CHECK (is_enabled IN (0, 1))
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_channel_servers_wire_name
    ON channel_servers (wire_name);

CREATE UNIQUE INDEX IF NOT EXISTS uq_channel_servers_sort_order
    ON channel_servers (sort_order);

CREATE TABLE IF NOT EXISTS channels (
    channel_id    INTEGER NOT NULL PRIMARY KEY,
    server_id     INTEGER NOT NULL,
    channel_no    INTEGER NOT NULL,
    wire_name     TEXT    NOT NULL,
    max_users     INTEGER NOT NULL,
    current_users INTEGER NOT NULL DEFAULT 0,
    endpoint_host TEXT    NOT NULL,
    endpoint_port INTEGER NOT NULL,
    is_enabled    INTEGER NOT NULL DEFAULT 1,
    CHECK (channel_id >= 0),
    CHECK (channel_no BETWEEN 0 AND 65535),
    CHECK (length(wire_name) BETWEEN 1 AND 20),
    CHECK (max_users >= 0),
    CHECK (current_users >= 0),
    CHECK (current_users <= max_users),
    CHECK (length(endpoint_host) BETWEEN 7 AND 15),
    CHECK (endpoint_port BETWEEN 1 AND 65535),
    CHECK (is_enabled IN (0, 1)),
    FOREIGN KEY (server_id) REFERENCES channel_servers (server_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_channels_server_number
    ON channels (server_id, channel_no);

CREATE UNIQUE INDEX IF NOT EXISTS uq_channels_server_wire_name
    ON channels (server_id, wire_name);

-- 端口到频道的反查是游戏服 accept 时的热路径：客户端连上某个游戏端口后，
-- 服务端必须立即据此确定 server_no / channel_no 才能构造首包。
CREATE UNIQUE INDEX IF NOT EXISTS uq_channels_endpoint_port
    ON channels (endpoint_port);

CREATE TABLE IF NOT EXISTS account_character_selection_slots (
    account_id INTEGER NOT NULL,
    slot_index INTEGER NOT NULL,
    value_i16  INTEGER NOT NULL,
    flag_u16   INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (account_id, slot_index),
    CHECK (slot_index BETWEEN 0 AND 72),
    CHECK (value_i16 BETWEEN -32768 AND 32767),
    CHECK (flag_u16 BETWEEN 0 AND 65535),
    CHECK (updated_at >= 0),
    FOREIGN KEY (account_id) REFERENCES accounts (account_id)
);

CREATE TABLE IF NOT EXISTS character_id_allocator (
    singleton         INTEGER NOT NULL PRIMARY KEY,
    next_character_id INTEGER NOT NULL,
    CHECK (singleton = 1),
    CHECK (next_character_id BETWEEN 1 AND 65536)
);

CREATE TABLE IF NOT EXISTS characters (
    character_id INTEGER NOT NULL PRIMARY KEY,
    account_id   INTEGER NOT NULL,
    slot_index   INTEGER NOT NULL,
    name         TEXT    NOT NULL,
    class_id     INTEGER NOT NULL,
    level        INTEGER NOT NULL,
    town_id      INTEGER NOT NULL DEFAULT 38,
    area_id      INTEGER NOT NULL DEFAULT 1,
    position_x   INTEGER NOT NULL DEFAULT 561,
    position_y   INTEGER NOT NULL DEFAULT 234,
    town_state   INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL,
    -- 累计经验。110 的满级累计经验约 1.2e10，超出 u32；SQLite 的 INTEGER 是 64 位，
    -- 协议上则是一对 u32（见 TownSelfStatsBody）。等级由它推出，两者都存是为了
    -- 让 CHECK 与既有的角色列表路径继续成立。
    experience     INTEGER NOT NULL DEFAULT 0,
    -- 转职分支（低 4 位）与觉醒阶段（高 4 位），在自身实体记录里打包成一个字节。
    -- 它们同时决定 16 级之后用 .chr 的哪张 [growtype N]。
    grow_type      INTEGER NOT NULL DEFAULT 0,
    sub_grow_type  INTEGER NOT NULL DEFAULT 0,
    ex_equip_slot_flags INTEGER NOT NULL DEFAULT 0 CHECK (ex_equip_slot_flags BETWEEN 0 AND 255),
    bonus_sp INTEGER NOT NULL DEFAULT 0 CHECK (bonus_sp BETWEEN 0 AND 65535),
    bonus_tp INTEGER NOT NULL DEFAULT 0 CHECK (bonus_tp BETWEEN 0 AND 65535),
    favorite_position INTEGER NOT NULL DEFAULT 0 CHECK (favorite_position BETWEEN 0 AND 5),
    -- 新角色首次进城时若 >0，TutorialFlagHandler 在进城序列里把它推入对应副本号的首房；
    -- 客户端 .act 里的 [[ON START TUTORIAL DUNGEON]] 会触发 cinematic 开场动画。
    -- 教程流程结束或后续进城前被 TownEntryHandler 清成 0。
    -- 副本号取自 PVF `map/cataclysm/newtutorial/<职业>/<首房>.map` 的 `[[dungeon]] id`。
    pending_tutorial_dungeon_id INTEGER NOT NULL DEFAULT 0 CHECK (pending_tutorial_dungeon_id >= 0),
    CHECK (character_id >= 0),
    CHECK (experience >= 0),
    CHECK (grow_type BETWEEN 0 AND 15),
    CHECK (sub_grow_type BETWEEN 0 AND 15),
    CHECK (slot_index BETWEEN 0 AND 65535),
    CHECK (length(name) BETWEEN 1 AND 32),
    CHECK (class_id BETWEEN 0 AND 65535),
    CHECK (level BETWEEN 1 AND 110),
    CHECK (town_id >= 0),
    CHECK (area_id >= 0),
    CHECK (position_x BETWEEN -32768 AND 32767),
    CHECK (position_y BETWEEN -32768 AND 32767),
    CHECK (town_state BETWEEN 0 AND 255),
    CHECK (created_at >= 0),
    CHECK (updated_at >= 0),
    FOREIGN KEY (account_id) REFERENCES accounts (account_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_characters_account_slot
    ON characters (account_id, slot_index);

CREATE UNIQUE INDEX IF NOT EXISTS uq_characters_name
    ON characters (name);

-- 教程 / 新手指引的 flag 索引，一行一个。
--
-- 已交付的任务。客户端点"完成"时发 (1,34) FINISH_QUEST，服务端回同操作码的成功响应。
-- 单独一张表而不是给 character_quests 加列：CREATE TABLE IF NOT EXISTS 对已有存档是
-- 幂等的，加列则要额外的 ALTER 迁移。
CREATE TABLE IF NOT EXISTS character_finished_quests (
    character_id INTEGER NOT NULL,
    quest_id     INTEGER NOT NULL,
    finished_at  INTEGER NOT NULL,
    PRIMARY KEY (character_id, quest_id),
    CHECK (quest_id BETWEEN 0 AND 65535),
    CHECK (finished_at >= 0),
    FOREIGN KEY (character_id) REFERENCES characters (character_id)
);

-- 客户端为教程与各种 UI 指引维护一张 102 项的字节数组（下标 = flag 索引，置 1 表示
-- "这条已经看过"）。服务端在 (1,4) 角色选择响应里下发已看过的索引，客户端每看完一条
-- 就用 (1,143) CHANGE_TUTORIAL_FLAG 报回来。布局与上限见 Protocol 侧的 TutorialFlags。
-- 玩家接下的任务。客户端点"接受"时发 (1,31) ACCEPT_QUEST，服务端回同操作码的成功
-- 响应；这里记下来，进城时用来判断哪些任务还是"可接"、哪些已经在进行中。
-- **副本选择界面能不能看见节点也取决于它**：客户端按副本 .dgn 的 [quest list] 过滤，
-- 一条都不在任务管理器里就把节点丢掉。
CREATE TABLE IF NOT EXISTS character_quests (
    character_id INTEGER NOT NULL,
    quest_id     INTEGER NOT NULL,
    accepted_at  INTEGER NOT NULL,
    PRIMARY KEY (character_id, quest_id),
    CHECK (quest_id BETWEEN 0 AND 65535),
    CHECK (accepted_at >= 0),
    FOREIGN KEY (character_id) REFERENCES characters (character_id)
);

CREATE TABLE IF NOT EXISTS character_quest_progress (
    character_id INTEGER NOT NULL,
    quest_id INTEGER NOT NULL,
    trigger_value INTEGER NOT NULL DEFAULT 1 CHECK (trigger_value BETWEEN 0 AND 4294967295),
    answer_index INTEGER NOT NULL DEFAULT -1 CHECK (answer_index BETWEEN -1 AND 255),
    PRIMARY KEY (character_id, quest_id),
    FOREIGN KEY (character_id, quest_id) REFERENCES character_quests (character_id, quest_id)
);

CREATE TABLE IF NOT EXISTS character_tutorial_flags (
    character_id INTEGER NOT NULL,
    flag_index   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL,
    PRIMARY KEY (character_id, flag_index),
    CHECK (flag_index BETWEEN 0 AND 101),
    CHECK (updated_at >= 0),
    FOREIGN KEY (character_id) REFERENCES characters (character_id)
);

CREATE TABLE IF NOT EXISTS account_dungeon_life_dialogue (
    account_id INTEGER NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    npc_id INTEGER NOT NULL CHECK(npc_id > 0),
    progress INTEGER NOT NULL CHECK(progress BETWEEN 1 AND 255),
    updated_at INTEGER NOT NULL CHECK(updated_at >= 0),
    PRIMARY KEY(account_id,npc_id)
);

CREATE TABLE IF NOT EXISTS character_story_digest (
    character_id INTEGER NOT NULL PRIMARY KEY,
    last_level INTEGER NOT NULL CHECK (last_level BETWEEN 1 AND 110),
    updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
    FOREIGN KEY (character_id) REFERENCES characters (character_id) ON DELETE CASCADE
);

-- 角色的物品：背包、穿戴栏、时装栏、仓库全在这一张表里，靠 list_type 分空间。
--
-- 空间与槽位的划分照 86JP（S4A21）的 InventoryListType：0 = 主背包、1 = 时装背包、
-- 2 = 个人仓库、3 = 穿戴栏、7 = 宠物栏、12 = 账号仓库。主背包里 0/1/2 三个槽是
-- **虚拟槽**（金币 / 复活币 / 胜点），它们的 item_id 就是 0/1/2、count 是数量——
-- **判断空槽不能只看 item_id == 0**，那是 86JP 明确记下来的一个坑。
--
-- 86JP 把每格存成一个 99 字节的 ItemCore BLOB，这里没有照抄：那 99 个字节是它自己
-- 客户端（A21）的字段集，而 110 的线上条目是 165 字节、只有前 22 字节逐字段对得上。
-- 存成显式的列，缺什么加什么，比存一团解释不了的字节强。
--
-- 空槽不写行。
-- instance_value 是**装备的品级随机种子**（客户端自己掷，服务端只给种子），
-- 堆叠物为 0。它不是数量：线上条目里同一个字段对堆叠物才是数量。
-- 生成之后必须固定——重新登录、进出仓库、穿上脱下都不能变，否则同一把武器的攻击力会自己跳。
CREATE TABLE IF NOT EXISTS character_items (
    character_id   INTEGER NOT NULL,
    list_type      INTEGER NOT NULL,
    slot_index     INTEGER NOT NULL,
    item_id        INTEGER NOT NULL,
    count          INTEGER NOT NULL DEFAULT 1,
    durability     INTEGER NOT NULL DEFAULT 0,
    instance_value INTEGER NOT NULL DEFAULT 0,
    random_options BLOB NOT NULL DEFAULT X'',
    avatar_sockets BLOB NOT NULL DEFAULT X'',
    clone_appearance_id INTEGER NOT NULL DEFAULT 0 CHECK(clone_appearance_id >= 0),
    reinforcement INTEGER NOT NULL DEFAULT 0 CHECK(reinforcement BETWEEN 0 AND 31),
    refinement INTEGER NOT NULL DEFAULT 0 CHECK(refinement BETWEEN 0 AND 8),
    fusion_item TEXT NOT NULL DEFAULT '',
 bakal_state TEXT NOT NULL DEFAULT '',
 transferred_option_mask INTEGER NOT NULL DEFAULT 0,
 enchant_card_id INTEGER NOT NULL DEFAULT 0,
 enchant_upgrade INTEGER NOT NULL DEFAULT 0,
 mist_imbued INTEGER NOT NULL DEFAULT 0 CHECK(mist_imbued IN (0,1)),
    updated_at     INTEGER NOT NULL,
    PRIMARY KEY (character_id, list_type, slot_index),
    CHECK (list_type >= 0),
    CHECK (slot_index >= 0),
    CHECK (item_id >= 0),
    CHECK (count >= 0),
    CHECK (durability >= 0),
    CHECK (instance_value >= 0),
    FOREIGN KEY (character_id) REFERENCES characters (character_id)
);

CREATE INDEX IF NOT EXISTS character_items_by_item
    ON character_items (character_id, item_id);

-- UTC calendar-day claims: gifts are account-wide (scope=0), weapons per character.
CREATE TABLE IF NOT EXISTS account_neo_claims (
    account_id INTEGER NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    scope INTEGER NOT NULL CHECK(scope >= 0),
    kind INTEGER NOT NULL CHECK(kind IN (0,1)),
    claim_day INTEGER NOT NULL,
    PRIMARY KEY(account_id, scope, kind)
);

-- The immutable quality seed follows the equipment through inventory moves.
CREATE TABLE IF NOT EXISTS character_neo_rentals (
    character_id INTEGER NOT NULL REFERENCES characters(character_id) ON DELETE CASCADE,
    item_id INTEGER NOT NULL,
    instance_value INTEGER NOT NULL CHECK(instance_value >= 100000),
    expires_at INTEGER NOT NULL,
    PRIMARY KEY(character_id, item_id, instance_value)
);


-- 角色学到的技能。
--
-- **只存玩家自己点出来的那一份等级**，白送的等级不进这张表：白送的取值由客户端自己的
-- .chr 决定（见 SkillCatalog.FreeBaseline），跟着等级和转职方向走，存下来只会在角色升级
-- 或转职之后变成一份对不上的旧数据。
--
-- SP 余额同样不存：它是"等级给的总量减去这张表花掉的"，与同为 US 线的 90 版参考实现一致。
--
-- slot 是技能栏的格子号，由服务端分配并且必须稳定——它就是客户端快捷栏上的位置。
CREATE TABLE IF NOT EXISTS character_skills (
    character_id INTEGER NOT NULL,
    tree         INTEGER NOT NULL DEFAULT 0,
    skill_id     INTEGER NOT NULL,
    level        INTEGER NOT NULL,
    slot         INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL,
    PRIMARY KEY (character_id, tree, skill_id),
    CHECK (tree >= 0),
    CHECK (skill_id > 0),
    CHECK (level >= 0),
    CHECK (slot >= 0),
    FOREIGN KEY (character_id) REFERENCES characters (character_id)
);

CREATE INDEX IF NOT EXISTS character_skills_by_slot
    ON character_skills (character_id, tree, slot);

CREATE TABLE IF NOT EXISTS system_mail (
    mail_id INTEGER PRIMARY KEY AUTOINCREMENT,
    character_id INTEGER NOT NULL REFERENCES characters(character_id),
    request_key TEXT NOT NULL UNIQUE,
    sender TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    claimed INTEGER NOT NULL DEFAULT 0 CHECK(claimed IN (0,1)),
    list_type INTEGER NOT NULL CHECK(list_type IN (0,1,7,43)),
    item_id INTEGER NOT NULL CHECK(item_id>=0),
    count INTEGER NOT NULL CHECK(count>0),
    durability INTEGER NOT NULL CHECK(durability>=0),
    instance_value INTEGER NOT NULL CHECK(instance_value>=0),
    fusion_item TEXT NOT NULL DEFAULT '',
 bakal_state TEXT NOT NULL DEFAULT '',
 transferred_option_mask INTEGER NOT NULL DEFAULT 0,
 enchant_card_id INTEGER NOT NULL DEFAULT 0,
 enchant_upgrade INTEGER NOT NULL DEFAULT 0,
 mist_imbued INTEGER NOT NULL DEFAULT 0 CHECK(mist_imbued IN (0,1))
);
CREATE INDEX IF NOT EXISTS system_mail_recipient ON system_mail(character_id,mail_id);

-- 技能快捷栏的摆放。
--
-- **整块原样存、原样发回。** 客户端在 C1/439 里把整张表一次性报上来（2026-09-06 实机：
-- 1,028 字节语义体 = u32 长度 1024 + 1024 字节的表，空格子是 0xFFFFFFFF），拖动一次
-- 报一次。表里那 1024 字节的内部结构没有逆出来，也**不需要**逆出来——服务端要做的只是
-- 记住玩家摆成什么样，下次原样还给他。
--
-- 不存的话玩家每次重登快捷栏都回到服务端分配的默认位置，表现就是"拖进去的技能没了"。
CREATE TABLE IF NOT EXISTS character_quickslots (
    character_id INTEGER NOT NULL PRIMARY KEY,
    payload      BLOB    NOT NULL,
    updated_at   INTEGER NOT NULL,
    FOREIGN KEY (character_id) REFERENCES characters (character_id)
);

CREATE TABLE IF NOT EXISTS character_creatures (
    creature_id INTEGER PRIMARY KEY AUTOINCREMENT CHECK (creature_id BETWEEN 1 AND 2147483647),
    character_id INTEGER NOT NULL REFERENCES characters(character_id),
    item_id INTEGER NOT NULL CHECK (item_id > 0),
    satiety INTEGER NOT NULL DEFAULT 100 CHECK (satiety BETWEEN 0 AND 100),
    level INTEGER NOT NULL DEFAULT 1 CHECK (level BETWEEN 1 AND 255),
    experience INTEGER NOT NULL DEFAULT 0 CHECK (experience BETWEEN 0 AND 4294967295),
    name TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS character_creatures_by_character ON character_creatures(character_id);

-- Durable GM receipts and mail tombstones preserve replay protection.
CREATE TABLE IF NOT EXISTS gm_operations (
 request_id TEXT PRIMARY KEY, payload TEXT NOT NULL, before_json TEXT NOT NULL,
 result_json TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS gm_deleted_mail (
 mail_id INTEGER PRIMARY KEY REFERENCES system_mail(mail_id), deleted_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS gm_inventory_revisions (
 character_id INTEGER NOT NULL, list_type INTEGER NOT NULL, slot_index INTEGER NOT NULL,
 revision INTEGER NOT NULL, PRIMARY KEY(character_id,list_type,slot_index)
);
CREATE TRIGGER IF NOT EXISTS gm_inventory_insert AFTER INSERT ON character_items BEGIN
 INSERT INTO gm_inventory_revisions VALUES(NEW.character_id,NEW.list_type,NEW.slot_index,1)
 ON CONFLICT(character_id,list_type,slot_index) DO UPDATE SET revision=revision+1;
END;
CREATE TRIGGER IF NOT EXISTS gm_inventory_update AFTER UPDATE ON character_items BEGIN
 INSERT INTO gm_inventory_revisions VALUES(OLD.character_id,OLD.list_type,OLD.slot_index,1)
 ON CONFLICT(character_id,list_type,slot_index) DO UPDATE SET revision=revision+1;
 INSERT INTO gm_inventory_revisions SELECT NEW.character_id,NEW.list_type,NEW.slot_index,1
 WHERE NEW.character_id<>OLD.character_id OR NEW.list_type<>OLD.list_type OR NEW.slot_index<>OLD.slot_index
 ON CONFLICT(character_id,list_type,slot_index) DO UPDATE SET revision=revision+1;
END;
CREATE TRIGGER IF NOT EXISTS gm_inventory_delete AFTER DELETE ON character_items BEGIN
 INSERT INTO gm_inventory_revisions VALUES(OLD.character_id,OLD.list_type,OLD.slot_index,1)
 ON CONFLICT(character_id,list_type,slot_index) DO UPDATE SET revision=revision+1;
END;
CREATE TABLE IF NOT EXISTS account_cubes (
    account_id INTEGER NOT NULL REFERENCES accounts(account_id),
    item_id INTEGER NOT NULL CHECK(item_id IN (3033,3034,3035,3036,3037,3262)),
    count INTEGER NOT NULL CHECK(count BETWEEN 0 AND 2147483647),
    PRIMARY KEY(account_id,item_id)
);

-- 110US account settings; raw bounded preference blob, no credentials.
CREATE TABLE IF NOT EXISTS account_client_settings (
 account_id INTEGER PRIMARY KEY REFERENCES accounts(account_id) ON DELETE CASCADE,
 options BLOB NOT NULL CHECK(length(options)=492)
);

-- Native keyboard profiles: ordinary jobs and Creator have separate tables.
CREATE TABLE IF NOT EXISTS account_hotkeys (
 account_id INTEGER NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
 key_type INTEGER NOT NULL CHECK(key_type IN (0,1)),
 bindings BLOB NOT NULL CHECK(length(bindings) <= 1399),
 PRIMARY KEY(account_id,key_type)
);

CREATE TABLE IF NOT EXISTS character_inventory_expansion (
 character_id INTEGER PRIMARY KEY REFERENCES characters(character_id) ON DELETE CASCADE,
 expansion INTEGER NOT NULL CHECK(expansion IN (0,8,16))
);

CREATE TABLE IF NOT EXISTS character_hotkeys (
 character_id INTEGER NOT NULL REFERENCES characters(character_id) ON DELETE CASCADE,
 key_type INTEGER NOT NULL CHECK(key_type IN (0,1)),
 bindings BLOB NOT NULL CHECK(length(bindings) <= 1399),
 PRIMARY KEY(character_id,key_type)
);

-- Per-character BUFF selection and references to real owned item instances.
CREATE TABLE IF NOT EXISTS character_buff_swap (
 character_id INTEGER PRIMARY KEY REFERENCES characters(character_id) ON DELETE CASCADE,
 skill_id INTEGER NOT NULL CHECK(skill_id BETWEEN 0 AND 65535)
);
CREATE TABLE IF NOT EXISTS buff_swap_registrations (
 character_id INTEGER NOT NULL REFERENCES characters(character_id) ON DELETE CASCADE,
 target_slot INTEGER NOT NULL CHECK(target_slot BETWEEN 0 AND 35),
 source_list INTEGER NOT NULL CHECK(source_list IN (0,1,2,3,7,45)),
 source_slot INTEGER NOT NULL CHECK(source_slot BETWEEN 0 AND 65534),
 PRIMARY KEY(character_id,target_slot)
);
-- Location references are removed with the instance, even for GM/database writes.
-- Move/sort explicitly restore their original references under the same transaction.
CREATE TRIGGER IF NOT EXISTS buff_swap_deleted AFTER DELETE ON character_items BEGIN
 DELETE FROM buff_swap_registrations WHERE character_id=OLD.character_id
 AND source_list=OLD.list_type AND source_slot=OLD.slot_index;
END;
CREATE TRIGGER IF NOT EXISTS buff_swap_replaced AFTER UPDATE ON character_items
WHEN NEW.item_id<>OLD.item_id OR NEW.instance_value<>OLD.instance_value
 OR NEW.list_type<>OLD.list_type OR NEW.slot_index<>OLD.slot_index OR NEW.count=0 BEGIN
 DELETE FROM buff_swap_registrations WHERE character_id=OLD.character_id
 AND source_list=OLD.list_type AND source_slot=OLD.slot_index;
END;

-- Account-wide, reward-free Explorer equipment tutorial. Consumed with its item.
CREATE TABLE IF NOT EXISTS account_explorer_tutorial (
 account_id INTEGER PRIMARY KEY REFERENCES accounts(account_id) ON DELETE CASCADE,
 item_id INTEGER NOT NULL CHECK(item_id > 0),
 registered_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS character_cube_contract (
 character_id INTEGER PRIMARY KEY REFERENCES characters(character_id) ON DELETE CASCADE,
 selection INTEGER NOT NULL CHECK(selection BETWEEN 0 AND 5 OR selection=255)
);
CREATE TABLE IF NOT EXISTS character_wish_items (
 character_id INTEGER NOT NULL REFERENCES characters(character_id) ON DELETE CASCADE,
 kind INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 1),
 slot INTEGER NOT NULL CHECK(slot BETWEEN 0 AND 4),
 item_id INTEGER NOT NULL CHECK(item_id > 0),
 PRIMARY KEY(character_id,kind,slot),
 UNIQUE(character_id,kind,item_id)
);
-- Native equipment-specificity selections; inventory carriers are converted with a receipt.
CREATE TABLE IF NOT EXISTS character_read_synopses (
 character_id INTEGER NOT NULL REFERENCES characters(character_id) ON DELETE CASCADE,
 synopsis_id INTEGER NOT NULL CHECK(synopsis_id >= 0),
 PRIMARY KEY(character_id, synopsis_id)
);
CREATE TABLE IF NOT EXISTS character_equipment_specificity (
 character_id INTEGER PRIMARY KEY REFERENCES characters(character_id) ON DELETE CASCADE,
 state_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS equipment_specificity_receipts (
 character_id INTEGER NOT NULL REFERENCES characters(character_id) ON DELETE CASCADE,
 source TEXT NOT NULL,
 item_json TEXT NOT NULL,
 PRIMARY KEY(character_id,source)
);
-- A card's payment, complete inventory delivery and receipt commit together.
-- Run GUIDs are generated by the server; reconnecting starts a new run.
CREATE TABLE IF NOT EXISTS dungeon_card_claims (
    character_id INTEGER NOT NULL REFERENCES characters(character_id) ON DELETE CASCADE,
    receipt TEXT NOT NULL,
    PRIMARY KEY (character_id, receipt)
);

CREATE TABLE IF NOT EXISTS character_cargo_state (
 character_id INTEGER PRIMARY KEY REFERENCES characters(character_id) ON DELETE CASCADE,
 capacity INTEGER NOT NULL DEFAULT 8 CHECK(capacity BETWEEN 8 AND 264)
);
CREATE TABLE IF NOT EXISTS account_cargo_state (
 account_id INTEGER PRIMARY KEY REFERENCES accounts(account_id) ON DELETE CASCADE,
 capacity INTEGER NOT NULL DEFAULT 0 CHECK(capacity BETWEEN 0 AND 240)
);
CREATE TABLE IF NOT EXISTS account_cargo_items (
 account_id INTEGER NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
 list_type INTEGER NOT NULL CHECK(list_type=12), slot_index INTEGER NOT NULL,
 item_id INTEGER NOT NULL, count INTEGER NOT NULL, durability INTEGER NOT NULL,
 instance_value INTEGER NOT NULL DEFAULT 0, random_options BLOB NOT NULL,
 avatar_sockets BLOB NOT NULL, clone_appearance_id INTEGER NOT NULL DEFAULT 0,
 reinforcement INTEGER NOT NULL DEFAULT 0, refinement INTEGER NOT NULL DEFAULT 0,
 fusion_item TEXT NOT NULL DEFAULT '',
 bakal_state TEXT NOT NULL DEFAULT '',
 transferred_option_mask INTEGER NOT NULL DEFAULT 0,
 enchant_card_id INTEGER NOT NULL DEFAULT 0,
 enchant_upgrade INTEGER NOT NULL DEFAULT 0,
 mist_imbued INTEGER NOT NULL DEFAULT 0 CHECK(mist_imbued IN (0,1)),
 updated_at INTEGER NOT NULL, PRIMARY KEY(account_id,list_type,slot_index)
);

CREATE TABLE IF NOT EXISTS character_second_cargo_state (character_id INTEGER PRIMARY KEY REFERENCES characters(character_id) ON DELETE CASCADE, capacity INTEGER NOT NULL DEFAULT 8 CHECK(capacity BETWEEN 8 AND 264));

-- C331 overrides survive skill refunds/resets; only C332 clears them all.
CREATE TABLE IF NOT EXISTS character_skill_commands (
 character_id INTEGER NOT NULL REFERENCES characters(character_id) ON DELETE CASCADE,
 skill_id INTEGER NOT NULL CHECK(skill_id BETWEEN 0 AND 65535),
 command BLOB NOT NULL CHECK(length(command) BETWEEN 1 AND 5),
 PRIMARY KEY(character_id,skill_id)
);

-- A paid normal Bakal attempt survives reconnects. Completion/abandonment are
-- deliberately not exposed until the corresponding raid flow is implemented.
CREATE TABLE IF NOT EXISTS character_bakal_admissions (
    character_id INTEGER PRIMARY KEY REFERENCES characters(character_id) ON DELETE CASCADE,
    run_id TEXT NOT NULL UNIQUE CHECK(length(run_id)=32),
    started_at INTEGER NOT NULL CHECK(started_at>0)
);

-- Immutable random outcome for a paid attempt. Asset delivery uses the existing
-- inventory + reward-receipt transaction; generating a plan never grants assets.
CREATE TABLE IF NOT EXISTS character_bakal_reward_plans (
    character_id INTEGER NOT NULL REFERENCES characters(character_id) ON DELETE CASCADE,
    run_id TEXT NOT NULL CHECK(length(run_id)=32),
    plan TEXT NOT NULL CHECK(length(plan) BETWEEN 2 AND 65536),
    created_at INTEGER NOT NULL,
    PRIMARY KEY(character_id,run_id)
);

CREATE TABLE IF NOT EXISTS character_bakal_auctions (
    character_id INTEGER NOT NULL,
    run_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK(length(state) BETWEEN 2 AND 8192),
    PRIMARY KEY(character_id,run_id),
    FOREIGN KEY(character_id,run_id) REFERENCES character_bakal_reward_plans(character_id,run_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS character_dungeon_admissions (
 character_id INTEGER NOT NULL REFERENCES characters(character_id) ON DELETE CASCADE,
 dungeon_id INTEGER NOT NULL, week TEXT NOT NULL, admission_id TEXT NOT NULL,
 PRIMARY KEY(character_id,dungeon_id,week,admission_id)
);

CREATE TABLE IF NOT EXISTS account_npc_shop_purchases (
 account_id INTEGER NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
 item_id INTEGER NOT NULL, rule_key TEXT NOT NULL, period_key TEXT NOT NULL,
 quantity INTEGER NOT NULL CHECK(quantity > 0),
 PRIMARY KEY(account_id,item_id,rule_key,period_key)
);
CREATE TABLE IF NOT EXISTS character_npc_shop_purchases (
 character_id INTEGER NOT NULL REFERENCES characters(character_id) ON DELETE CASCADE,
 item_id INTEGER NOT NULL, rule_key TEXT NOT NULL, period_key TEXT NOT NULL,
 quantity INTEGER NOT NULL CHECK(quantity > 0),
 PRIMARY KEY(character_id,item_id,rule_key,period_key)
);

-- The US110 Custom Option Book is character-specific, including common options.
CREATE TABLE IF NOT EXISTS character_custom_options (
 character_id INTEGER NOT NULL REFERENCES characters(character_id) ON DELETE CASCADE,
 part INTEGER NOT NULL CHECK(part BETWEEN 14 AND 25 AND part<>24),
 option_id INTEGER NOT NULL CHECK(option_id BETWEEN 1 AND 65535),
 quantity INTEGER NOT NULL CHECK(quantity>0),
 PRIMARY KEY(character_id,part,option_id)
);
