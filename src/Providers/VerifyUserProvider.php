<?php
namespace Toddish\Verify\Providers;

use Illuminate\Contracts\Auth\UserProvider,
	Illuminate\Auth\EloquentUserProvider,
	Illuminate\Contracts\Hashing\Hasher as HasherContract,
	Illuminate\Contracts\Auth\Authenticatable as UserContract;

class VerifyUserProvider extends EloquentUserProvider implements UserProvider
{
	public function retrieveByCredentials(array $credentials)
	{
		if (array_key_exists('identifier', $credentials))
		{
			foreach (config('verify.identified_by') as $identified_by)
			{
				$query = $this->createModel()
					->newQuery()
					->where($identified_by, $credentials['identifier']);

				$this->appendQueryConditions($query, $credentials, ['password', 'identifier']);

				if ($query->count() !== 0)
				{
					break;
				}
			}
		}
		else
		{
			$query = $this->createModel()->newQuery();
			$this->appendQueryConditions($query, $credentials);
		}

		return $query->first();
	}

	protected function appendQueryConditions($query, $conditions, $exclude = ['password'])
	{
		foreach ($conditions as $key => $value)
		{
			if (!in_array($key, $exclude))
			{
				$query->where($key, $value);
			}
		}
	}

	public function validateCredentials(UserContract $user, array $credentials)
	{
        $plain = $credentials['password'];
        // Is user password is valid?
        if(!$this->hasher->check($user->salt.$plain, $user->getAuthPassword())) {
            throw new UserPasswordIncorrectException('User password is incorrect');
        }

        // Valid user, but are they verified?
        if (!$user->verified) {
            throw new UserUnverifiedException('User is unverified');
        }

        // Is the user disabled?
        if ($user->disabled) {
            throw new UserDisabledException('User is disabled');
        }

        // Is the user deleted?
        if ($user->deleted_at !== NULL) {
            throw new UserDeletedException('User is deleted');
        }

        return true;
	}

	public function isVerified(UserContract $user)
	{
		return $user->verified;
	}

	public function isDisabled(UserContract $user)
	{
		return $user->disabled;
	}
}

class UserNotFoundException extends \Exception {};
class UserUnverifiedException extends \Exception {};
class UserDisabledException extends \Exception {};
class UserDeletedException extends \Exception {};
class UserPasswordIncorrectException extends \Exception {};