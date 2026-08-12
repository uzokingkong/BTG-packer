use std::hint::black_box;

pub const GAME_WIDTH: i32 = 800;
pub const GAME_HEIGHT: i32 = 600;

#[derive(Clone, Copy)]
pub struct DataCube {
    pub x: i32,
    pub y: i32,
    pub speed: i32,
    pub val: u64,
    pub is_secure: bool,
}

#[derive(Clone, Copy)]
pub struct MatrixDrop {
    pub x: i32,
    pub y: i32,
    pub speed: i32,
    pub glyph: u16,
}

pub struct CyberDefenderGame {
    pub player_x: i32,
    pub player_y: i32,
    pub player_speed: i32,
    pub score: u64,
    pub health: i32,
    pub combo: u32,
    pub frame_counter: u64,
    pub cubes: Vec<DataCube>,
    pub drops: Vec<MatrixDrop>,
}

impl CyberDefenderGame {
    pub fn new(seed: u64) -> Self {
        let mut cubes = Vec::new();
        let mut drops = Vec::new();

        let mut rng = seed;
        let mut next_random = || {
            rng ^= rng >> 12;
            rng ^= rng << 25;
            rng ^= rng >> 27;
            rng = rng.wrapping_mul(0x2545F4914F6CDD1D);
            rng
        };

        // Create 16 Data Cubes
        for i in 0..16i32 {
            let r = next_random();
            cubes.push(DataCube {
                x: ((r % 720) as i32 + 40),
                y: -(i * 50 + 20),
                speed: ((r % 3) as i32 + 2),
                val: r,
                is_secure: (r & 1) == 0,
            });
        }

        // Create 32 Matrix Drops
        for i in 0..32i32 {
            let r = next_random();
            drops.push(MatrixDrop {
                x: i * 25 + 10,
                y: -((r % 500) as i32),
                speed: ((r % 4) as i32 + 3),
                glyph: (0x30 + (r % 10)) as u16,
            });
        }

        Self {
            player_x: 400,
            player_y: 520,
            player_speed: 6,
            score: 0,
            health: 100,
            combo: 0,
            frame_counter: 0,
            cubes,
            drops,
        }
    }

    #[inline(never)]
    pub fn move_player(&mut self, dx: i32, dy: i32) {
        self.player_x = (self.player_x + dx * self.player_speed).clamp(40, 760);
        self.player_y = (self.player_y + dy * self.player_speed).clamp(100, 560);
    }

    #[inline(never)]
    pub fn step(&mut self, auto_ai: bool) {
        self.frame_counter += 1;

        if auto_ai {
            // Simple AI auto-pilot targeting closest secure cube
            let p_x = self.player_x;
            let mut target_x = p_x;
            let mut min_dist = 9999i32;

            for cube in &self.cubes {
                if cube.y > 0 && cube.y < 540 {
                    let dist = (cube.x - p_x).abs();
                    if dist < min_dist {
                        min_dist = dist;
                        target_x = cube.x;
                    }
                }
            }

            if target_x < p_x - 4 {
                self.move_player(-1, 0);
            } else if target_x > p_x + 4 {
                self.move_player(1, 0);
            }
        }

        // Update Matrix Drops
        for drop in &mut self.drops {
            drop.y += drop.speed;
            if drop.y > 600 {
                drop.y = -20;
                drop.glyph = (0x30 + ((self.frame_counter + drop.x as u64) % 10)) as u16;
            }
        }

        // Update Data Cubes & Collisions
        for i in 0..self.cubes.len() {
            let mut c = self.cubes[i];
            c.y += c.speed;

            // Check collision with player drone
            let dx = (c.x - self.player_x).abs();
            let dy = (c.y - self.player_y).abs();

            if dx < 35 && dy < 25 {
                if c.is_secure {
                    self.score += 100 + (self.combo as u64 * 10);
                    self.combo += 1;
                } else {
                    self.health = (self.health - 10).max(0);
                    self.combo = 0;
                }
                c.y = -100;
                c.x = ((self.frame_counter * 0x1337 + (i as u64 * 77)) % 720 + 40) as i32;
            } else if c.y > 600 {
                c.y = -50;
                c.x = ((self.frame_counter * 0x4141 + (i as u64 * 99)) % 720 + 40) as i32;
            }

            self.cubes[i] = c;
        }
    }

    #[inline(never)]
    pub fn compute_game_state_hash(&self) -> u64 {
        let mut hash = 0xCBF29CE484222325u64;
        hash ^= (self.score).rotate_left(13);
        hash ^= (self.health as u64).rotate_left(7);
        hash ^= (self.combo as u64).rotate_left(3);
        hash ^= (self.player_x as u64).rotate_left(17);
        hash ^= (self.player_y as u64).rotate_left(23);

        for cube in &self.cubes {
            hash ^= (cube.x as u64) ^ (cube.y as u64).rotate_left(11);
            hash = hash.wrapping_mul(0x100000001B3);
        }

        black_box(hash)
    }
}

#[inline(never)]
pub fn run_game_simulation_benchmark(seed: u64, num_frames: u32) -> u64 {
    let mut game = CyberDefenderGame::new(seed);
    for _ in 0..num_frames {
        game.step(true);
    }
    game.compute_game_state_hash()
}
