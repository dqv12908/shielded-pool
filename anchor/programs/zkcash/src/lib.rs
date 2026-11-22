use anchor_lang::prelude::*;
use light_hasher::Poseidon;
use anchor_lang::solana_program::sysvar::rent::Rent;
use ark_ff::PrimeField;
use ark_bn254::Fr;
use anchor_spl::token::{self, Token, TokenAccount, Mint, Transfer as SplTransfer};
use anchor_spl::associated_token::AssociatedToken;

// Fork of Privacy Cash with every admin power removed: no admin key, no fee
// config, no deposit limits, no token allowlist. Once the upgrade authority is
// revoked, nobody can change, pause, or tax this pool.
declare_id!("12tHGHwtEci5KSM8agUEXuk3FYnWN4nMidE3oFccj1pJ");

pub mod merkle_tree;
pub mod utils;
pub mod groth16;
pub mod errors;

use merkle_tree::MerkleTree;

// Constants
const MERKLE_TREE_HEIGHT: u8 = 26;
const ROOT_HISTORY_SIZE: u8 = 100;

#[program]
pub mod zkcash {
    use crate::utils::{verify_proof, VERIFYING_KEY};

    use super::*;

    /**
     * Create the SOL pool. Permissionless and one-shot: the PDAs can only be
     * created once, and the caller gains no privileges.
     */
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let tree_account = &mut ctx.accounts.tree_account.load_init()?;
        tree_account.next_index = 0;
        tree_account.root_index = 0;
        tree_account.bump = ctx.bumps.tree_account;
        tree_account.height = MERKLE_TREE_HEIGHT;
        tree_account.root_history_size = ROOT_HISTORY_SIZE;

        MerkleTree::initialize::<Poseidon>(tree_account)?;

        ctx.accounts.tree_token_account.bump = ctx.bumps.tree_token_account;
        ctx.accounts.global_config.bump = ctx.bumps.global_config;

        msg!("SOL pool initialized, tree height: {}", MERKLE_TREE_HEIGHT);
        Ok(())
    }

    /**
     * Create the pool for an SPL token. Permissionless for any mint owned by
     * the classic SPL Token program; the caller gains no privileges.
     */
    pub fn initialize_tree_account_for_spl_token(
        ctx: Context<InitializeTreeAccountForSplToken>,
    ) -> Result<()> {
        let tree_account = &mut ctx.accounts.tree_account.load_init()?;
        tree_account.next_index = 0;
        tree_account.root_index = 0;
        tree_account.bump = ctx.bumps.tree_account;
        tree_account.height = MERKLE_TREE_HEIGHT;
        tree_account.root_history_size = ROOT_HISTORY_SIZE;

        MerkleTree::initialize::<Poseidon>(tree_account)?;

        msg!("SPL pool initialized for mint: {}", ctx.accounts.mint.key());
        Ok(())
    }

    /**
     * Users deposit or withdraw SOL from the program.
     *
     * Reentrant attacks are not possible, because nullifier creation is checked by anchor first.
     */
    pub fn transact(ctx: Context<Transact>, proof: Proof, ext_data_minified: ExtDataMinified, encrypted_output1: Vec<u8>, encrypted_output2: Vec<u8>) -> Result<()> {
        let tree_account = &mut ctx.accounts.tree_account.load_mut()?;

        // Reconstruct full ExtData from minified version and context accounts
        let ext_data = ExtData::from_minified(&ctx, ext_data_minified);

        // check if proof.root is in the tree_account's proof history
        require!(
            MerkleTree::is_known_root(&tree_account, proof.root),
            ErrorCode::UnknownRoot
        );

        // check if the ext_data hashes to the same ext_data in the proof
        let calculated_ext_data_hash = utils::calculate_complete_ext_data_hash(
            ext_data.recipient,
            ext_data.ext_amount,
            &encrypted_output1,
            &encrypted_output2,
            ext_data.fee,
            ext_data.fee_recipient,
            ext_data.mint_address,
        )?;

        require!(
            Fr::from_le_bytes_mod_order(&calculated_ext_data_hash) == Fr::from_be_bytes_mod_order(&proof.ext_data_hash),
            ErrorCode::ExtDataHashMismatch
        );

        require!(
            utils::check_public_amount(ext_data.ext_amount, ext_data.fee, proof.public_amount),
            ErrorCode::InvalidPublicAmountData
        );
        
        let ext_amount = ext_data.ext_amount;
        // There is no protocol fee. `fee` is the relayer tip that the user chose
        // and committed to inside the proof (via ext_data_hash).
        let fee = ext_data.fee;

        // verify the proof
        require!(verify_proof(proof.clone(), VERIFYING_KEY), ErrorCode::InvalidProof);

        let tree_token_account_info = ctx.accounts.tree_token_account.to_account_info();
        let rent = Rent::get()?;
        let rent_exempt_minimum = rent.minimum_balance(tree_token_account_info.data_len());

        if ext_amount > 0 {
            // If it's a deposit, transfer the SOL to the tree token account.
            anchor_lang::system_program::transfer(
                CpiContext::new(
                    ctx.accounts.system_program.to_account_info(),
                    anchor_lang::system_program::Transfer {
                        from: ctx.accounts.signer.to_account_info(),
                        to: ctx.accounts.tree_token_account.to_account_info(),
                    },
                ),
                ext_amount as u64,
            )?;
        } else if ext_amount < 0 {
            // PDA can't directly sign transactions, so we need to transfer SOL via try_borrow_mut_lamports
            // No limit on withdrawals
            let recipient_account_info = ctx.accounts.recipient.to_account_info();

            let ext_amount_abs: u64 = ext_amount.checked_neg()
                .ok_or(ErrorCode::ArithmeticOverflow)?
                .try_into()
                .map_err(|_| ErrorCode::InvalidExtAmount)?;
            
            let total_required = ext_amount_abs
                .checked_add(fee)
                .ok_or(ErrorCode::ArithmeticOverflow)?
                .checked_add(rent_exempt_minimum)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
            
            require!(
                tree_token_account_info.lamports() >= total_required,
                ErrorCode::InsufficientFundsForWithdrawal
            );

            let tree_token_balance = tree_token_account_info.lamports();
            let recipient_balance = recipient_account_info.lamports();
            
            let new_tree_token_balance = tree_token_balance.checked_sub(ext_amount_abs)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
            let new_recipient_balance = recipient_balance.checked_add(ext_amount_abs)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
                
            **tree_token_account_info.try_borrow_mut_lamports()? = new_tree_token_balance;
            **recipient_account_info.try_borrow_mut_lamports()? = new_recipient_balance;
        }
        
        if fee > 0 {
            let fee_recipient_account_info = ctx.accounts.fee_recipient_account.to_account_info();

            if ext_amount >= 0 {
                let total_required = fee
                    .checked_add(rent_exempt_minimum)
                    .ok_or(ErrorCode::ArithmeticOverflow)?;
                
                require!(
                    tree_token_account_info.lamports() >= total_required,
                    ErrorCode::InsufficientFundsForFee
                );
            }

            let tree_token_balance = tree_token_account_info.lamports();
            let fee_recipient_balance = fee_recipient_account_info.lamports();
            
            let new_tree_token_balance = tree_token_balance.checked_sub(fee)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
            let new_fee_recipient_balance = fee_recipient_balance.checked_add(fee)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
                
            **tree_token_account_info.try_borrow_mut_lamports()? = new_tree_token_balance;
            **fee_recipient_account_info.try_borrow_mut_lamports()? = new_fee_recipient_balance;
        }

        let next_index_to_insert = tree_account.next_index;
        MerkleTree::append::<Poseidon>(proof.output_commitments[0], tree_account)?;
        MerkleTree::append::<Poseidon>(proof.output_commitments[1], tree_account)?;

        let second_index = next_index_to_insert.checked_add(1)
            .ok_or(ErrorCode::ArithmeticOverflow)?;

        emit!(CommitmentData {
            index: next_index_to_insert,
            commitment: proof.output_commitments[0],
            encrypted_output: encrypted_output1.to_vec(),
        });

        emit!(CommitmentData {
            index: second_index,
            commitment: proof.output_commitments[1],
            encrypted_output: encrypted_output2.to_vec(),
        });
        
        Ok(())
    }

    /**
     * Users deposit or withdraw SPL tokens from the program.
     * 
     * Reentrant attacks are not possible, because nullifier creation is checked by anchor first.
     */
    pub fn transact_spl(ctx: Context<TransactSpl>, proof: Proof, ext_data_minified: ExtDataMinified, encrypted_output1: Vec<u8>, encrypted_output2: Vec<u8>) -> Result<()> {
        let tree_account = &mut ctx.accounts.tree_account.load_mut()?;

        // Validate signer's token account ownership and mint
        require!(
            ctx.accounts.signer_token_account.owner == ctx.accounts.signer.key(),
            ErrorCode::InvalidTokenAccount
        );
        require!(
            ctx.accounts.signer_token_account.mint == ctx.accounts.mint.key(),
            ErrorCode::InvalidTokenAccountMintAddress
        );

        // Reconstruct full ExtData from minified version and context accounts
        let ext_data = ExtData::from_minified_spl(&ctx, ext_data_minified);

        // check if proof.root is in the tree_account's proof history
        require!(
            MerkleTree::is_known_root(&tree_account, proof.root),
            ErrorCode::UnknownRoot
        );

        let calculated_ext_data_hash = utils::calculate_complete_ext_data_hash(
            ext_data.recipient,
            ext_data.ext_amount,
            &encrypted_output1,
            &encrypted_output2,
            ext_data.fee,
            ext_data.fee_recipient,
            ext_data.mint_address,
        )?;

        require!(
            Fr::from_le_bytes_mod_order(&calculated_ext_data_hash) == Fr::from_be_bytes_mod_order(&proof.ext_data_hash),
            ErrorCode::ExtDataHashMismatch
        );

        require!(
            utils::check_public_amount(ext_data.ext_amount, ext_data.fee, proof.public_amount),
            ErrorCode::InvalidPublicAmountData
        );
        
        let ext_amount = ext_data.ext_amount;
        // No protocol fee; `fee` is the user-chosen relayer tip bound by the proof.
        let fee = ext_data.fee;

        // verify the proof
        require!(verify_proof(proof.clone(), VERIFYING_KEY), ErrorCode::InvalidProof);

        if ext_amount > 0 {
            token::transfer(
                CpiContext::new(
                    ctx.accounts.token_program.to_account_info(),
                    SplTransfer {
                        from: ctx.accounts.signer_token_account.to_account_info(),
                        to: ctx.accounts.tree_ata.to_account_info(),
                        authority: ctx.accounts.signer.to_account_info(),
                    },
                ),
                ext_amount as u64,
            )?;
        } else if ext_amount < 0 {
            let ext_amount_abs: u64 = ext_amount.checked_neg()
                .ok_or(ErrorCode::ArithmeticOverflow)?
                .try_into()
                .map_err(|_| ErrorCode::InvalidExtAmount)?;
            
            // SPL Token withdrawal: transfer from tree's ATA to recipient's token account
            let bump = &[ctx.accounts.global_config.bump];
            let seeds: &[&[u8]] = &[b"global_config", bump];
            let signer_seeds = &[seeds];
            
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    SplTransfer {
                        from: ctx.accounts.tree_ata.to_account_info(),
                        to: ctx.accounts.recipient_token_account.to_account_info(),
                        authority: ctx.accounts.global_config.to_account_info(),
                    },
                    signer_seeds,
                ),
                ext_amount_abs,
            )?;
        }
        
        if fee > 0 {
            // SPL Token fee payment: transfer from tree's ATA to fee recipient's token account
            let bump = &[ctx.accounts.global_config.bump];
            let seeds: &[&[u8]] = &[b"global_config", bump];
            let signer_seeds = &[seeds];
            
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    SplTransfer {
                        from: ctx.accounts.tree_ata.to_account_info(),
                        to: ctx.accounts.fee_recipient_ata.to_account_info(),
                        authority: ctx.accounts.global_config.to_account_info(),
                    },
                    signer_seeds,
                ),
                fee,
            )?;
        }

        let next_index_to_insert = tree_account.next_index;
        MerkleTree::append::<Poseidon>(proof.output_commitments[0], tree_account)?;
        MerkleTree::append::<Poseidon>(proof.output_commitments[1], tree_account)?;

        let second_index = next_index_to_insert.checked_add(1)
            .ok_or(ErrorCode::ArithmeticOverflow)?;

        emit!(SplCommitmentData {
            index: next_index_to_insert,
            mint_address: ext_data.mint_address,
            commitment: proof.output_commitments[0],
            encrypted_output: encrypted_output1.to_vec(),
        });

        emit!(SplCommitmentData {
            index: second_index,
            mint_address: ext_data.mint_address,
            commitment: proof.output_commitments[1],
            encrypted_output: encrypted_output2.to_vec(),
        });
        
        Ok(())
    }
}

#[event]
pub struct CommitmentData {
    pub index: u64,
    pub commitment: [u8; 32],
    pub encrypted_output: Vec<u8>,
}

#[event]
pub struct SplCommitmentData {
    pub index: u64,
    pub mint_address: Pubkey,
    pub commitment: [u8; 32],
    pub encrypted_output: Vec<u8>,
}

// all public inputs needs to be in big endian format
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct Proof {
    pub proof_a: [u8; 64],
    pub proof_b: [u8; 128],
    pub proof_c: [u8; 64],
    pub root: [u8; 32],
    pub public_amount: [u8; 32],
    pub ext_data_hash: [u8; 32],
    pub input_nullifiers: [[u8; 32]; 2],
    pub output_commitments: [[u8; 32]; 2],
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ExtData {
    pub recipient: Pubkey,
    pub ext_amount: i64,
    pub fee: u64,
    pub fee_recipient: Pubkey,
    pub mint_address: Pubkey,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ExtDataMinified {
    pub ext_amount: i64,
    pub fee: u64,
}

impl ExtData {
    fn from_minified(ctx: &Context<Transact>, minified: ExtDataMinified) -> Self {
        Self {
            recipient: ctx.accounts.recipient.key(),
            ext_amount: minified.ext_amount,
            fee: minified.fee,
            fee_recipient: ctx.accounts.fee_recipient_account.key(),
            mint_address: utils::SOL_ADDRESS,
        }
    }

    fn from_minified_spl(ctx: &Context<TransactSpl>, minified: ExtDataMinified) -> Self {
        Self {
            recipient: ctx.accounts.recipient_token_account.key(),
            ext_amount: minified.ext_amount,
            fee: minified.fee,
            fee_recipient: ctx.accounts.fee_recipient_ata.key(),
            mint_address: ctx.accounts.mint.key(),
        }
    }
}

#[derive(Accounts)]
#[instruction(proof: Proof, ext_data_minified: ExtDataMinified, encrypted_output1: Vec<u8>, encrypted_output2: Vec<u8>)]
pub struct Transact<'info> {
    #[account(
        mut,
        seeds = [b"merkle_tree"],
        bump = tree_account.load()?.bump
    )]
    pub tree_account: AccountLoader<'info, MerkleTreeAccount>,
    
    /// Nullifier account to mark the first input as spent.
    /// Using `init` without `init_if_needed` ensures that the transaction
    /// will automatically fail with a system program error if this nullifier
    /// has already been used (i.e., if the account already exists).
    #[account(
        init,
        payer = signer,
        space = 8 + std::mem::size_of::<NullifierAccount>(),
        seeds = [b"nullifier0", proof.input_nullifiers[0].as_ref()],
        bump
    )]
    pub nullifier0: Account<'info, NullifierAccount>,
    
    /// Nullifier account to mark the second input as spent.
    /// Using `init` without `init_if_needed` ensures that the transaction
    /// will automatically fail with a system program error if this nullifier
    /// has already been used (i.e., if the account already exists).
    #[account(
        init,
        payer = signer,
        space = 8 + std::mem::size_of::<NullifierAccount>(),
        seeds = [b"nullifier1", proof.input_nullifiers[1].as_ref()],
        bump
    )]
    pub nullifier1: Account<'info, NullifierAccount>,

    #[account(
        seeds = [b"nullifier0", proof.input_nullifiers[1].as_ref()],
        bump
    )]
    pub nullifier2: SystemAccount<'info>,
    
    #[account(
        seeds = [b"nullifier1", proof.input_nullifiers[0].as_ref()],
        bump
    )]
    pub nullifier3: SystemAccount<'info>,
    
    #[account(
        mut,
        seeds = [b"tree_token"],
        bump = tree_token_account.bump
    )]
    pub tree_token_account: Account<'info, TreeTokenAccount>,

    #[account(mut)]
    /// CHECK: user should be able to send funds to any types of accounts
    pub recipient: UncheckedAccount<'info>,
    
    #[account(mut)]
    /// CHECK: user should be able to send fees to any types of accounts
    pub fee_recipient_account: UncheckedAccount<'info>,
    
    /// The account that is signing the transaction
    #[account(mut)]
    pub signer: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(proof: Proof, ext_data_minified: ExtDataMinified, encrypted_output1: Vec<u8>, encrypted_output2: Vec<u8>)]
pub struct TransactSpl<'info> {
    #[account(
        mut,
        seeds = [b"merkle_tree", mint.key().as_ref()],
        bump = tree_account.load()?.bump
    )]
    pub tree_account: AccountLoader<'info, MerkleTreeAccount>,
    
    /// Nullifier account to mark the first input as spent.
    /// Using `init` without `init_if_needed` ensures that the transaction
    /// will automatically fail with a system program error if this nullifier
    /// has already been used (i.e., if the account already exists).
    #[account(
        init,
        payer = signer,
        space = 8 + std::mem::size_of::<NullifierAccount>(),
        seeds = [b"nullifier0", proof.input_nullifiers[0].as_ref()],
        bump
    )]
    pub nullifier0: Account<'info, NullifierAccount>,
    
    /// Nullifier account to mark the second input as spent.
    /// Using `init` without `init_if_needed` ensures that the transaction
    /// will automatically fail with a system program error if this nullifier
    /// has already been used (i.e., if the account already exists).
    #[account(
        init,
        payer = signer,
        space = 8 + std::mem::size_of::<NullifierAccount>(),
        seeds = [b"nullifier1", proof.input_nullifiers[1].as_ref()],
        bump
    )]
    pub nullifier1: Account<'info, NullifierAccount>,

    #[account(
        seeds = [b"nullifier0", proof.input_nullifiers[1].as_ref()],
        bump
    )]
    pub nullifier2: SystemAccount<'info>,
    
    #[account(
        seeds = [b"nullifier1", proof.input_nullifiers[0].as_ref()],
        bump
    )]
    pub nullifier3: SystemAccount<'info>,
    
    #[account(
        seeds = [b"global_config"],
        bump = global_config.bump
    )]
    pub global_config: Account<'info, GlobalConfig>,
    
    /// The account that is signing the transaction
    #[account(mut)]
    pub signer: Signer<'info>,
    
    /// SPL Token mint account (required for token operations)
    pub mint: Account<'info, Mint>,
    
    /// Signer's token account (source for deposits)
    #[account(mut)]
    pub signer_token_account: Account<'info, TokenAccount>,

    /// CHECK: user should be able to send funds to any types of accounts
    pub recipient: UncheckedAccount<'info>,
    
    /// Recipient's token account (destination for withdrawals)
    /// It's relayer's job to account for the rent of the recipient_token_account, to prevent rent
    /// griefing attacks on the relayer's wallet. Relayer adds instruction to init the account.
    #[account(
        mut,
        token::mint = mint,
        token::authority = recipient
    )]
    pub recipient_token_account: Account<'info, TokenAccount>,
    
    /// Tree's associated token account (destination for deposits, source for withdrawals)
    /// Created automatically if it doesn't exist
    #[account(
        init_if_needed,
        payer = signer,
        associated_token::mint = mint,
        associated_token::authority = global_config
    )]
    pub tree_ata: Account<'info, TokenAccount>,
    
    /// Fee recipient's associated token account (auto-derived from fee_recipient_account + mint)
    /// Fee recipient ATA is guaranteed to exist for supported tokens
    /// CHECK: Validated in the instruction logic
    #[account(mut)]
    pub fee_recipient_ata: UncheckedAccount<'info>,
    
    /// SPL Token program
    pub token_program: Program<'info, Token>,
    
    /// Associated Token program
    pub associated_token_program: Program<'info, AssociatedToken>,
    
    pub system_program: Program<'info, System>,
}


#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + std::mem::size_of::<MerkleTreeAccount>(),
        seeds = [b"merkle_tree"],
        bump
    )]
    pub tree_account: AccountLoader<'info, MerkleTreeAccount>,
    
    #[account(
        init,
        payer = payer,
        space = 8 + std::mem::size_of::<TreeTokenAccount>(),
        seeds = [b"tree_token"],
        bump
    )]
    pub tree_token_account: Account<'info, TreeTokenAccount>,
    
    #[account(
        init,
        payer = payer,
        space = 8 + std::mem::size_of::<GlobalConfig>(),
        seeds = [b"global_config"],
        bump
    )]
    pub global_config: Account<'info, GlobalConfig>,
    
    #[account(mut)]
    pub payer: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitializeTreeAccountForSplToken<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + std::mem::size_of::<MerkleTreeAccount>(),
        seeds = [b"merkle_tree", mint.key().as_ref()],
        bump
    )]
    pub tree_account: AccountLoader<'info, MerkleTreeAccount>,
    
    /// SPL Token mint account
    pub mint: Account<'info, Mint>,
    
    #[account(
        seeds = [b"global_config"],
        bump = global_config.bump
    )]
    pub global_config: Account<'info, GlobalConfig>,
    
    #[account(mut)]
    pub payer: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

/// Vault that holds pooled SOL. No authority: only proofs move funds out.
#[account]
pub struct TreeTokenAccount {
    pub bump: u8,
}

/// PDA that owns the SPL token vaults (signs withdrawals via seeds).
/// It carries no settings and no authority.
#[account]
pub struct GlobalConfig {
    pub bump: u8,
}

#[account]
pub struct NullifierAccount {
    /// This account's existence indicates that the nullifier has been used.
    /// No fields needed other than bump for PDA verification.
    pub bump: u8,
}

#[account(zero_copy)]
pub struct MerkleTreeAccount {
    pub next_index: u64,
    pub subtrees: [[u8; 32]; MERKLE_TREE_HEIGHT as usize],
    pub root: [u8; 32],
    pub root_history: [[u8; 32]; 100],
    pub root_index: u64,
    pub height: u8,
    pub root_history_size: u8,
    pub bump: u8,
    // The pub _padding: [u8; 5] is needed because of the #[account(zero_copy)] attribute.
    pub _padding: [u8; 5],
}

#[error_code]
pub enum ErrorCode {
    #[msg("Not authorized to perform this action")]
    Unauthorized,
    #[msg("External data hash does not match the one in the proof")]
    ExtDataHashMismatch,
    #[msg("Root is not known in the tree")]
    UnknownRoot,
    #[msg("Public amount is invalid")]
    InvalidPublicAmountData,
    #[msg("Insufficient funds for withdrawal")]
    InsufficientFundsForWithdrawal,
    #[msg("Insufficient funds for fee")]
    InsufficientFundsForFee,
    #[msg("Proof is invalid")]
    InvalidProof,
    #[msg("Invalid fee: fee must be less than MAX_ALLOWED_VAL (2^248).")]
    InvalidFee,
    #[msg("Invalid ext amount: absolute ext_amount must be less than MAX_ALLOWED_VAL (2^248).")]
    InvalidExtAmount,
    #[msg("Public amount calculation resulted in an overflow/underflow.")]
    PublicAmountCalculationError,
    #[msg("Arithmetic overflow/underflow occurred")]
    ArithmeticOverflow,
    #[msg("Deposit limit exceeded")]
    DepositLimitExceeded,
    #[msg("Invalid fee rate: must be between 0 and 10000 basis points")]
    InvalidFeeRate,
    #[msg("Fee recipient does not match global configuration")]
    InvalidFeeRecipient,
    #[msg("Fee amount is below minimum required (must be at least (1 - fee_error_margin) * expected_fee)")]
    InvalidFeeAmount,
    #[msg("Recipient account does not match the ExtData recipient")]
    RecipientMismatch,
    #[msg("Merkle tree is full: cannot add more leaves")]
    MerkleTreeFull,
    #[msg("Invalid token account: account is not owned by the token program")]
    InvalidTokenAccount,
    #[msg("Invalid mint address: mint address is not allowed")]
    InvalidMintAddress,
    #[msg("Invalid token account mint address")]
    InvalidTokenAccountMintAddress,
}