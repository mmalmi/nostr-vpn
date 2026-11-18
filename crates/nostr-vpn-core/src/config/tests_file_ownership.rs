    #[cfg(unix)]
    #[test]
    fn private_files_prefer_user_owned_parent_over_stale_root_owned_file() {
        assert_eq!(
            super::preferred_private_file_owner(Some((0, 0)), Some((501, 20))),
            Some((501, 20))
        );
        assert_eq!(
            super::preferred_private_file_owner(Some((502, 20)), Some((501, 20))),
            Some((502, 20))
        );
        assert_eq!(
            super::preferred_private_file_owner(None, Some((501, 20))),
            Some((501, 20))
        );
        assert_eq!(
            super::preferred_private_file_owner(None, Some((0, 0))),
            None
        );
    }
