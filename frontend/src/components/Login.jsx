import React, { useState } from 'react'
import logo from '../assets/logo.jpeg'
import registerHero from '../assets/register-hero.png'
import { confirmRegistration, login, register } from '../services/api'
import './Login.css'

function Login({ onAuthSuccess, theme }) {
  const [mode, setMode] = useState('login')
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    confirmPassword: '',
    verificationCode: '',
  })
  const [error, setError] = useState('')
  const [info, setInfo] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [verificationSent, setVerificationSent] = useState(false)

  const isRegister = mode === 'register'
  void theme

  const handleChange = (e) => {
    const { name, value } = e.target
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }))
    setError('')
    setInfo('')
  }

  const resetRegisterState = () => {
    setVerificationSent(false)
    setFormData((prev) => ({
      ...prev,
      password: '',
      confirmPassword: '',
      verificationCode: '',
    }))
  }

  const switchMode = (nextMode) => {
    setMode(nextMode)
    setError('')
    setInfo('')
    resetRegisterState()
  }

  const sendCode = async () => {
    await register(formData.email, formData.password)
    setVerificationSent(true)
    setInfo('Код подтверждения был отправлен на вашу электронную почту')
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setInfo('')
    setIsLoading(true)

    const { email, password, confirmPassword, verificationCode } = formData

    if (!email || !password || (isRegister && !confirmPassword)) {
      setError('Пожалуйста, заполните все обязательные поля')
      setIsLoading(false)
      return
    }

    if (isRegister && password !== confirmPassword) {
      setError('Пароли не совпадают')
      setIsLoading(false)
      return
    }

    if (isRegister && password.length < 6) {
      setError('Пароль должен содержать не менее 6 символов')
      setIsLoading(false)
      return
    }

    try {
      if (isRegister) {
        if (!verificationSent) {
          await sendCode()
          return
        }

        if (!verificationCode) {
          setError('Введите код верификации из письма')
          return
        }
      }

      const authResponse = isRegister
        ? await confirmRegistration(email, verificationCode)
        : await login(email, password)

      localStorage.setItem('token', authResponse.token)
      localStorage.setItem('user', JSON.stringify(authResponse.user))
      onAuthSuccess(authResponse.user)
    } catch (err) {
      setError(err.message || 'Ошибка авторизации')
    } finally {
      setIsLoading(false)
    }
  }

  const handleResendCode = async () => {
    setError('')
    setInfo('')
    setIsLoading(true)
    try {
      await sendCode()
    } catch (err) {
      setError(err.message || 'Не удалось повторно отправить код')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="login-page-wrapper">
      <div
        className="login-hero-side"
        style={{ backgroundImage: `url(${registerHero})` }}
      >
        <div className="login-hero-content">
          <p className="login-hero-subtitle">
            Передовые технологии обнаружения мошенничества и сетевой анализ на базе
            искусственного интеллекта.
          </p>
        </div>
      </div>

      <div className="login-form-side">
        <div className="login-card-inner">
          <div className="login-header">
            <div className="login-logo-container">
              <img src={logo} alt="FinAnalytica" className="login-logo-img" />
            </div>
            <h2 className="login-title">
              {isRegister ? 'Регистрация' : 'С возвращением'}
            </h2>
            <p className="login-subtitle">
              {isRegister
                ? 'Присоединяйтесь к новому поколению финансового аудита.'
                : 'Введите свои данные для доступа к досье.'}
            </p>
          </div>

          <form className="login-form" onSubmit={handleSubmit}>
            {error && <div className="login-alert login-alert-error">{error}</div>}
            {info && <div className="login-alert login-alert-info">{info}</div>}

            <div className="login-input-group">
              <label className="login-label">Email / Идентификатор</label>
              <input
                name="email"
                type="email"
                required
                value={formData.email}
                onChange={handleChange}
                className="login-input"
                placeholder="arkham@finanalytica.ai"
              />
            </div>

            <div className="login-input-group">
              <label className="login-label">Пароль / Ключ доступа</label>
              <input
                name="password"
                type="password"
                required
                value={formData.password}
                onChange={handleChange}
                className="login-input"
                placeholder="••••••••••••"
              />
            </div>

            {isRegister && (
              <>
                <div className="login-input-group">
                  <label className="login-label">Подтвердите пароль</label>
                  <input
                    name="confirmPassword"
                    type="password"
                    required
                    value={formData.confirmPassword}
                    onChange={handleChange}
                    className="login-input"
                    placeholder="••••••••••••"
                  />
                </div>
                {verificationSent && (
                  <div className="login-input-group">
                    <label className="login-label">Код верификации</label>
                    <input
                      name="verificationCode"
                      type="text"
                      required
                      value={formData.verificationCode}
                      onChange={handleChange}
                      className="login-input"
                      placeholder="Введите 6-значный код"
                    />
                  </div>
                )}
              </>
            )}

            <button type="submit" className="login-submit-btn" disabled={isLoading}>
              {isLoading
                ? (isRegister
                  ? (verificationSent ? 'Проверка...' : 'Отправка...')
                  : 'Авторизация...')
                : (isRegister
                  ? (verificationSent ? 'Создать аккаунт' : 'Получить код')
                  : 'Войти')}
            </button>

            {isRegister && verificationSent && (
              <button
                type="button"
                className="login-link-btn"
                style={{ width: '100%', marginTop: '10px' }}
                onClick={handleResendCode}
                disabled={isLoading}
              >
                Отправить код повторно
              </button>
            )}
          </form>

          <div className="login-footer-action">
            {isRegister ? (
              <span>
                Уже есть аккаунт?
                <button type="button" onClick={() => switchMode('login')} className="login-link-btn">
                  Войти
                </button>
              </span>
            ) : (
              <span>
                Новый пользователь?
                <button type="button" onClick={() => switchMode('register')} className="login-link-btn">
                  Зарегистрироваться
                </button>
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default Login
